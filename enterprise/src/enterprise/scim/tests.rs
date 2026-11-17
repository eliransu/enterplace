//! SCIM as the Cloudflare app's tests check it (cloud/tests/test_members.py and test_members_links.py, the SCIM
//! parts), with the request shapes Okta and Microsoft Entra ID document sending, against a real Postgres, plus the
//! license gate.
//!
//! Okta: https://developer.okta.com/docs/api/openapi/okta-scim/guides/scim-20
//! Entra: https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::enterprise::testing::*;

const BASE: &str = "/console/scim/v2";
const PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

struct Reply {
    status: StatusCode,
    body: Value,
    content_type: String,
}

/// A SCIM request as an identity provider sends it: a bearer token and a JSON body, no cookie and no origin.
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> Result<Reply, Error> {
    let request = Request::builder()
        .method(method)
        .uri(format!("{BASE}{path}"))
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/scim+json");
    let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
    let response = app.clone().oneshot(request.body(body)?).await?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = response.into_body().collect().await?.to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok(Reply {
        status,
        body,
        content_type,
    })
}

/// The SCIM token on a page, shown once.
fn token_in(page: &str) -> Option<String> {
    let rest = page.split("gscim_").nth(1)?;
    let hex: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
    (hex.len() == 64).then(|| format!("gscim_{hex}"))
}

/// A SCIM token, made by the admin key's owner session.
async fn new_token(gw: &Gateway, owner: &mut Browser) -> Result<String, Error> {
    let made = owner
        .go(&gw.app, "POST", "/console/scim/tokens", &[("name", "idp")])
        .await?;
    Ok(token_in(&made.text).ok_or(format!("no token: {}", made.text))?)
}

fn records(gw: &Gateway) -> Result<Vec<Value>, Error> {
    let log = std::fs::read_to_string(gw.dir.join("enterplace-audit.jsonl"))?;
    Ok(log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["event"] == "admin")
        .collect())
}

fn record<'a>(all: &'a [Value], action: &str) -> Result<&'a Value, Error> {
    Ok(all
        .iter()
        .rev()
        .find(|r| r["action"] == action)
        .ok_or(format!("{action} not recorded"))?)
}

async fn client(url: &str) -> Result<enterplace_server::store::tokio_postgres::Client, Error> {
    use enterplace_server::store::tokio_postgres;
    let config: tokio_postgres::Config = url.parse()?;
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    Ok(client)
}

/// The role and team of the person with `email`.
async fn role_team(url: &str, email: &str) -> Result<(String, String), Error> {
    let row = client(url)
        .await?
        .query_one(
            "SELECT role, team FROM enterprise_people WHERE email = $1",
            &[&email],
        )
        .await?;
    Ok((row.try_get(0)?, row.try_get(1)?))
}

/// The user Okta sends to create a person (its SCIM 2.0 guide, "Create the user").
fn okta_user(email: &str, given: &str, family: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": email,
        "name": { "givenName": given, "familyName": family },
        "emails": [{ "primary": true, "value": email, "type": "work" }],
        "displayName": format!("{given} {family}"),
        "locale": "en-US",
        "externalId": "00ujl29u0le5T6Aj10h7",
        "groups": [],
        "password": "1mz050nq",
        "active": true
    })
}

/// The user Entra ID sends to create a person (its SCIM guide, "Create User").
fn entra_user(email: &str, department: &str) -> Value {
    json!({
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        ],
        "externalId": "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef",
        "userName": email,
        "active": true,
        "addresses": [{ "primary": false, "type": "work", "country": "US" }],
        "displayName": "Test User",
        "emails": [{ "primary": true, "type": "work", "value": email }],
        "meta": { "resourceType": "User" },
        "name": { "formatted": "givenName familyName", "familyName": "familyName", "givenName": "givenName" },
        "roles": [],
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { "department": department }
    })
}

#[test]
fn filters_and_team_names() {
    assert_eq!(
        filter(r#"userName eq "a@b.co""#),
        Some(("username".into(), "a@b.co".into()))
    );
    assert_eq!(
        filter(r#"  displayName EQ "Platform Eng"  "#),
        Some(("displayname".into(), "Platform Eng".into()))
    );
    assert_eq!(filter(r#"userName sw "a""#), None);
    assert_eq!(filter("userName eq a"), None);
    assert_eq!(team_of("Platform Eng").as_deref(), Some("platform-eng"));
    assert_eq!(team_of(" R&D / Ops ").as_deref(), Some("r-d-ops"));
    assert_eq!(team_of("research.ml_1").as_deref(), Some("research.ml_1"));
    assert_eq!(team_of("!!!"), None);
}

#[tokio::test]
async fn discovery_is_what_okta_and_entra_read() -> Result<(), Error> {
    let Some(url) = database("scim_discovery").await? else {
        return Ok(());
    };
    let gw = gateway("scim_discovery", &url, &licensed(&["members", "scim"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let token = new_token(&gw, &mut owner).await?;

    let cfg = call(&gw.app, "GET", "/ServiceProviderConfig", &token, None).await?;
    assert_eq!(cfg.status, StatusCode::OK);
    assert_eq!(cfg.content_type, "application/scim+json");
    assert_eq!(cfg.body["patch"]["supported"], true);
    assert_eq!(cfg.body["filter"]["supported"], true);
    assert_eq!(cfg.body["bulk"]["supported"], false);
    assert_eq!(
        cfg.body["authenticationSchemes"][0]["type"],
        "oauthbearertoken"
    );

    let types = call(&gw.app, "GET", "/ResourceTypes", &token, None).await?;
    assert_eq!(types.status, StatusCode::OK);
    let ids: Vec<&str> = types.body["Resources"]
        .as_array()
        .ok_or("no Resources")?
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    assert_eq!(ids, ["User", "Group"]);
    let user_type = call(&gw.app, "GET", "/ResourceTypes/User", &token, None).await?;
    assert_eq!(user_type.body["endpoint"], "/Users");
    assert_eq!(user_type.body["schemaExtensions"][0]["schema"], ENTERPRISE);

    let schemas = call(&gw.app, "GET", "/Schemas", &token, None).await?;
    assert_eq!(schemas.status, StatusCode::OK);
    assert_eq!(schemas.body["totalResults"], 3);
    let user = call(&gw.app, "GET", &format!("/Schemas/{USER}"), &token, None).await?;
    let names: Vec<&str> = user.body["attributes"]
        .as_array()
        .ok_or("no attributes")?
        .iter()
        .filter_map(|a| a["name"].as_str())
        .collect();
    assert!(names.contains(&"userName") && names.contains(&"active"));

    // Entra's connection test: a filter for a userName no one has answers an empty list, not an error.
    let probe = call(
        &gw.app,
        "GET",
        "/Users?filter=userName+eq+%2207f6d8a6-1f2b-4a5e-b2d3-0c8f6b0a1e11%22",
        &token,
        None,
    )
    .await?;
    assert_eq!(probe.status, StatusCode::OK);
    assert_eq!(probe.body["totalResults"], 0);
    assert_eq!(probe.body["Resources"], json!([]));

    // Wrong, missing or revoked tokens are refused, in SCIM's error shape.
    let wrong = call(
        &gw.app,
        "GET",
        "/Users",
        &format!("gscim_{}", "0".repeat(64)),
        None,
    )
    .await?;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body["schemas"][0], ERROR);
    assert_eq!(wrong.body["status"], "401");
    assert!(
        wrong.body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("SCIM token")),
        "{}",
        wrong.body
    );
    let unknown = call(&gw.app, "GET", "/Things", &token, None).await?;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    let filter = call(
        &gw.app,
        "GET",
        "/Users?filter=title+sw+%22x%22",
        &token,
        None,
    )
    .await?;
    assert_eq!(filter.status, StatusCode::BAD_REQUEST);
    assert_eq!(filter.body["scimType"], "invalidFilter");
    Ok(())
}

#[tokio::test]
async fn okta_provisions_updates_and_deactivates_a_person() -> Result<(), Error> {
    let Some(url) = database("scim_okta").await? else {
        return Ok(());
    };
    let gw = gateway("scim_okta", &url, &licensed(&["members", "scim"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let token = new_token(&gw, &mut owner).await?;
    let email = "ada@example.com";

    // Okta looks the person up first, then creates them.
    let look = call(
        &gw.app,
        "GET",
        "/Users?filter=userName%20eq%20%22ada%40example.com%22&startIndex=1&count=100",
        &token,
        None,
    )
    .await?;
    assert_eq!(look.body["totalResults"], 0);
    let made = call(
        &gw.app,
        "POST",
        "/Users",
        &token,
        Some(okta_user(email, "Ada", "Lovelace")),
    )
    .await?;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
    let id = made.body["id"].as_str().ok_or("no id")?.to_string();
    assert_eq!(made.body["userName"], email);
    assert_eq!(made.body["active"], true);
    assert_eq!(made.body["externalId"], "00ujl29u0le5T6Aj10h7");
    assert_eq!(made.body["name"]["givenName"], "Ada");
    assert_eq!(made.body["meta"]["resourceType"], "User");
    assert!(
        made.body["meta"]["location"]
            .as_str()
            .is_some_and(|l| l.ends_with(&format!("{BASE}/Users/{id}")))
    );
    assert_eq!(
        role_team(&url, email).await?,
        ("viewer".into(), "default".into())
    );
    let again = call(
        &gw.app,
        "POST",
        "/Users",
        &token,
        Some(okta_user(email, "Ada", "Lovelace")),
    )
    .await?;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.body["scimType"], "uniqueness");

    // A person SCIM made has no password, so cannot sign in with one.
    let signin = Browser::default()
        .go(
            &gw.app,
            "POST",
            "/console/sign-in/password",
            &[("email", email), ("password", "1mz050nq")],
        )
        .await?;
    assert_eq!(signin.status, StatusCode::UNAUTHORIZED);

    let found = call(
        &gw.app,
        "GET",
        "/Users?filter=userName%20eq%20%22ada%40example.com%22&startIndex=1&count=100",
        &token,
        None,
    )
    .await?;
    assert_eq!(found.body["totalResults"], 1);
    assert_eq!(found.body["startIndex"], 1);
    assert_eq!(found.body["Resources"][0]["id"], id.as_str());
    let got = call(&gw.app, "GET", &format!("/Users/{id}"), &token, None).await?;
    assert_eq!(got.status, StatusCode::OK);

    // Okta updates a profile with PUT, the whole user.
    let mut changed = okta_user(email, "Ada", "King");
    changed["id"] = json!(id);
    let put = call(
        &gw.app,
        "PUT",
        &format!("/Users/{id}"),
        &token,
        Some(changed),
    )
    .await?;
    assert_eq!(put.status, StatusCode::OK, "{}", put.body);
    assert_eq!(put.body["name"]["familyName"], "King");
    assert_eq!(put.body["displayName"], "Ada King");
    // userName is the person's email, and keys are named with it: it does not change under them.
    let mut moved = okta_user("ada.king@example.com", "Ada", "King");
    moved["id"] = json!(id);
    let refused = call(&gw.app, "PUT", &format!("/Users/{id}"), &token, Some(moved)).await?;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.body["scimType"], "mutability");

    // Okta deactivates with a PATCH that has no path. Their keys go, everywhere.
    enterplace_core::keyfile::add_entry(
        email,
        "default",
        "enterplace_ada1_0123456789abcdef0123456789",
        false,
        &gw.keys,
    )?;
    enterplace_core::keyfile::add_entry(
        "Ada@Example.com",
        "default",
        "enterplace_ada2_0123456789abcdef0123456789",
        false,
        &gw.keys,
    )?;
    enterplace_core::keyfile::add_entry(
        "stays@example.com",
        "default",
        "enterplace_stay_0123456789abcdef0123456789",
        false,
        &gw.keys,
    )?;
    let off = call(
        &gw.app,
        "PATCH",
        &format!("/Users/{id}"),
        &token,
        Some(json!({
            "schemas": [PATCH_OP],
            "Operations": [{ "op": "replace", "value": { "active": false } }]
        })),
    )
    .await?;
    assert!(
        matches!(off.status, StatusCode::OK | StatusCode::NO_CONTENT),
        "{}",
        off.body
    );
    let keys = enterplace_core::config::read_keys(&gw.keys)?.unwrap_or_default();
    assert!(!keys.to_lowercase().contains(email), "{keys}");
    assert!(keys.contains("stays@example.com"));
    let gone = call(&gw.app, "GET", &format!("/Users/{id}"), &token, None).await?;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);

    let all = records(&gw)?;
    let added = record(&all, "member_added")?;
    assert_eq!(added["target"]["via"], "scim");
    assert!(
        added["person"]
            .as_str()
            .is_some_and(|p| p.starts_with("scim"))
    );
    let removed = record(&all, "member_removed")?;
    assert_eq!(removed["target"]["email"], email);
    assert_eq!(
        removed["target"]["keys_revoked"].as_array().map(Vec::len),
        Some(2)
    );
    record(&all, "member_changed")?;
    Ok(())
}

#[tokio::test]
async fn entra_provisions_updates_and_deactivates_a_person() -> Result<(), Error> {
    let Some(url) = database("scim_entra").await? else {
        return Ok(());
    };
    let gw = gateway("scim_entra", &url, &licensed(&["all"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let token = new_token(&gw, &mut owner).await?;
    let email = "Test_User_dfeef4c5@testuser.com";

    let made = call(
        &gw.app,
        "POST",
        "/Users",
        &token,
        Some(entra_user(email, "ops")),
    )
    .await?;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
    let id = made.body["id"].as_str().ok_or("no id")?.to_string();
    // Emails are kept in lower case, as the members port keeps them; Entra matches userName without case.
    assert_eq!(made.body["userName"], email.to_lowercase());
    assert_eq!(made.body[ENTERPRISE]["department"], "ops");
    let lower = email.to_lowercase();
    assert_eq!(
        role_team(&url, &lower).await?,
        ("viewer".into(), "ops".into())
    );

    // Entra matches by userName, and by externalId.
    let by_name = call(
        &gw.app,
        "GET",
        &format!("/Users?filter=userName+eq+%22{email}%22"),
        &token,
        None,
    )
    .await?;
    assert_eq!(by_name.body["totalResults"], 1);
    let by_external = call(
        &gw.app,
        "GET",
        "/Users?filter=externalId+eq+%220a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef%22",
        &token,
        None,
    )
    .await?;
    assert_eq!(by_external.body["Resources"][0]["id"], id.as_str());

    // Entra's PATCH: capitalised ops, a path on each, and the extension's attribute by its full name.
    let patched = call(
        &gw.app,
        "PATCH",
        &format!("/Users/{id}"),
        &token,
        Some(json!({
            "schemas": [PATCH_OP],
            "Operations": [
                { "op": "Replace", "path": "displayName", "value": "Grace Hopper" },
                { "op": "Add", "path": "name.givenName", "value": "Grace" },
                { "op": "Replace", "path": "name.familyName", "value": "Hopper" },
                { "op": "Replace", "path": "emails[type eq \"work\"].value", "value": lower },
                { "op": "Add", "path": "title", "value": "Rear Admiral" },
                { "op": "Replace", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "research" }
            ]
        })),
    )
    .await?;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    assert_eq!(patched.body["name"]["formatted"], "Grace Hopper");
    assert_eq!(
        role_team(&url, &lower).await?,
        ("viewer".into(), "research".into())
    );

    // A malformed PATCH says what to send.
    let bad = call(
        &gw.app,
        "PATCH",
        &format!("/Users/{id}"),
        &token,
        Some(json!({ "active": false })),
    )
    .await?;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.body["scimType"], "invalidSyntax");

    // Entra disables with the value as a string, "False".
    enterplace_core::keyfile::add_entry(
        &lower,
        "research",
        "enterplace_grace_0123456789abcdef012345678",
        false,
        &gw.keys,
    )?;
    let off = call(
        &gw.app,
        "PATCH",
        &format!("/Users/{id}"),
        &token,
        Some(json!({
            "schemas": [PATCH_OP],
            "Operations": [{ "op": "Replace", "path": "active", "value": "False" }]
        })),
    )
    .await?;
    assert!(
        matches!(off.status, StatusCode::OK | StatusCode::NO_CONTENT),
        "{}",
        off.body
    );
    let keys = enterplace_core::config::read_keys(&gw.keys)?.unwrap_or_default();
    assert!(!keys.contains(&lower), "{keys}");
    assert_eq!(
        call(&gw.app, "GET", &format!("/Users/{id}"), &token, None)
            .await?
            .status,
        StatusCode::NOT_FOUND
    );

    // Entra deletes with DELETE; a person who is not there answers 404.
    let second = call(
        &gw.app,
        "POST",
        "/Users",
        &token,
        Some(entra_user("second@example.com", "ops")),
    )
    .await?;
    let second_id = second.body["id"].as_str().ok_or("no id")?.to_string();
    let deleted = call(
        &gw.app,
        "DELETE",
        &format!("/Users/{second_id}"),
        &token,
        None,
    )
    .await?;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(
        call(
            &gw.app,
            "DELETE",
            &format!("/Users/{second_id}"),
            &token,
            None
        )
        .await?
        .status,
        StatusCode::NOT_FOUND
    );

    // A person created inactive is refused rather than made active.
    let mut inactive = entra_user("off@example.com", "ops");
    inactive["active"] = json!(false);
    assert_eq!(
        call(&gw.app, "POST", "/Users", &token, Some(inactive))
            .await?
            .status,
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn okta_and_entra_push_groups_as_teams() -> Result<(), Error> {
    let Some(url) = database("scim_groups").await? else {
        return Ok(());
    };
    let gw = gateway("scim_groups", &url, &licensed(&["members", "scim"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let token = new_token(&gw, &mut owner).await?;
    let mut ids = Vec::new();
    for email in ["one@example.com", "two@example.com"] {
        let made = call(
            &gw.app,
            "POST",
            "/Users",
            &token,
            Some(okta_user(email, "P", "Q")),
        )
        .await?;
        ids.push(made.body["id"].as_str().ok_or("no id")?.to_string());
    }
    let (one, two) = (&ids[0], &ids[1]);

    // Okta pushes a group empty, then adds members with a PATCH, and removes them by a filter in the path.
    let group = call(
        &gw.app,
        "POST",
        "/Groups",
        &token,
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Platform Eng",
            "members": []
        })),
    )
    .await?;
    assert_eq!(group.status, StatusCode::CREATED, "{}", group.body);
    let gid = group.body["id"].as_str().ok_or("no id")?.to_string();
    assert_eq!(group.body["displayName"], "Platform Eng");
    let added = call(
        &gw.app,
        "PATCH",
        &format!("/Groups/{gid}"),
        &token,
        Some(json!({
            "schemas": [PATCH_OP],
            "Operations": [{ "op": "add", "path": "members", "value": [
                { "value": one, "display": "one@example.com" },
                { "value": two, "display": "two@example.com" }
            ] }]
        })),
    )
    .await?;
    assert!(
        matches!(added.status, StatusCode::OK | StatusCode::NO_CONTENT),
        "{}",
        added.body
    );
    assert_eq!(role_team(&url, "one@example.com").await?.1, "platform-eng");
    let got = call(&gw.app, "GET", &format!("/Groups/{gid}"), &token, None).await?;
    assert_eq!(got.body["members"].as_array().map(Vec::len), Some(2));
    let user = call(&gw.app, "GET", &format!("/Users/{one}"), &token, None).await?;
    assert_eq!(user.body["groups"][0]["value"], gid.as_str());
    let removed = call(
        &gw.app,
        "PATCH",
        &format!("/Groups/{gid}"),
        &token,
        Some(json!({
            "schemas": [PATCH_OP],
            "Operations": [{ "op": "remove", "path": format!("members[value eq \"{two}\"]") }]
        })),
    )
    .await?;
    assert!(matches!(
        removed.status,
        StatusCode::OK | StatusCode::NO_CONTENT
    ));
    assert_eq!(
        role_team(&url, "two@example.com").await?,
        ("viewer".into(), "default".into())
    );
    // Okta renames with a replace that has no path; the team follows the name.
    let renamed = call(
        &gw.app,
        "PATCH",
        &format!("/Groups/{gid}"),
        &token,
        Some(json!({
            "schemas": [PATCH_OP],
            "Operations": [{ "op": "replace", "value": { "id": gid, "displayName": "Platform" } }]
        })),
    )
    .await?;
    assert!(matches!(
        renamed.status,
        StatusCode::OK | StatusCode::NO_CONTENT
    ));
    assert_eq!(role_team(&url, "one@example.com").await?.1, "platform");

    // Entra: a group with an externalId, found by displayName without its members, members added and removed by value.
    let research = call(
        &gw.app,
        "POST",
        "/Groups",
        &token,
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group", "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"],
            "externalId": "8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159",
            "displayName": "Research",
            "meta": { "resourceType": "Group" }
        })),
    )
    .await?;
    assert_eq!(research.status, StatusCode::CREATED, "{}", research.body);
    let rid = research.body["id"].as_str().ok_or("no id")?.to_string();
    let found = call(
        &gw.app,
        "GET",
        "/Groups?excludedAttributes=members&filter=displayName+eq+%22Research%22",
        &token,
        None,
    )
    .await?;
    assert_eq!(found.body["totalResults"], 1);
    assert!(found.body["Resources"][0].get("members").is_none());
    let entra_add = call(
        &gw.app,
        "PATCH",
        &format!("/Groups/{rid}"),
        &token,
        Some(json!({
            "schemas": [PATCH_OP],
            "Operations": [{ "op": "Add", "path": "members", "value": [{ "value": two }] }]
        })),
    )
    .await?;
    assert!(
        matches!(entra_add.status, StatusCode::OK | StatusCode::NO_CONTENT),
        "{}",
        entra_add.body
    );
    assert_eq!(role_team(&url, "two@example.com").await?.1, "research");

    // An owner marks a group as one whose members are admins; the role follows membership.
    let page = owner.go(&gw.app, "GET", "/console/scim", &[]).await?;
    assert!(
        page.text.contains("Research") && page.text.contains("research"),
        "{}",
        page.text
    );
    let marked = owner
        .go(
            &gw.app,
            "POST",
            "/console/scim/groups/role",
            &[("group_id", &rid), ("role", "admin")],
        )
        .await?;
    assert_eq!(marked.status, StatusCode::SEE_OTHER, "{}", marked.text);
    assert_eq!(
        role_team(&url, "two@example.com").await?,
        ("admin".into(), "research".into())
    );
    let entra_remove = call(
        &gw.app,
        "PATCH",
        &format!("/Groups/{rid}"),
        &token,
        Some(json!({
            "schemas": [PATCH_OP],
            "Operations": [{ "op": "Remove", "path": "members", "value": [{ "value": two }] }]
        })),
    )
    .await?;
    assert!(matches!(
        entra_remove.status,
        StatusCode::OK | StatusCode::NO_CONTENT
    ));
    assert_eq!(
        role_team(&url, "two@example.com").await?,
        ("viewer".into(), "default".into())
    );

    // A member who is not a person, and a name taken already, are refused.
    let stranger = call(
        &gw.app,
        "PATCH",
        &format!("/Groups/{rid}"),
        &token,
        Some(json!({
            "schemas": [PATCH_OP],
            "Operations": [{ "op": "Add", "path": "members", "value": [{ "value": "usr_nobody" }] }]
        })),
    )
    .await?;
    assert_eq!(stranger.status, StatusCode::BAD_REQUEST);
    let twin = call(
        &gw.app,
        "POST",
        "/Groups",
        &token,
        Some(json!({ "displayName": "Research" })),
    )
    .await?;
    assert_eq!(twin.status, StatusCode::CONFLICT);

    // PUT replaces the members; DELETE removes the group and its members return to the default team.
    let put = call(
        &gw.app,
        "PUT",
        &format!("/Groups/{rid}"),
        &token,
        Some(json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Research", "members": [{ "value": one }] })),
    )
    .await?;
    assert_eq!(put.status, StatusCode::OK, "{}", put.body);
    let deleted = call(&gw.app, "DELETE", &format!("/Groups/{gid}"), &token, None).await?;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(
        role_team(&url, "one@example.com").await?,
        ("admin".into(), "research".into())
    );
    assert_eq!(
        call(&gw.app, "GET", &format!("/Groups/{gid}"), &token, None)
            .await?
            .status,
        StatusCode::NOT_FOUND
    );

    let all = records(&gw)?;
    for action in [
        "group_created",
        "group_changed",
        "group_deleted",
        "scim_group_role_changed",
    ] {
        record(&all, action)?;
    }
    Ok(())
}

#[tokio::test]
async fn the_last_owner_cannot_be_deprovisioned() -> Result<(), Error> {
    let Some(url) = database("scim_owner").await? else {
        return Ok(());
    };
    let gw = gateway("scim_owner", &url, &licensed(&["members", "scim"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let token = new_token(&gw, &mut owner).await?;
    let made = call(
        &gw.app,
        "POST",
        "/Users",
        &token,
        Some(okta_user("boss@example.com", "B", "Oss")),
    )
    .await?;
    let id = made.body["id"].as_str().ok_or("no id")?.to_string();
    let promoted = owner
        .go(
            &gw.app,
            "POST",
            "/console/members/role",
            &[("user_id", &id), ("role", "owner"), ("team", "default")],
        )
        .await?;
    assert_eq!(promoted.status, StatusCode::SEE_OTHER, "{}", promoted.text);
    let refused = call(&gw.app, "DELETE", &format!("/Users/{id}"), &token, None).await?;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert_eq!(refused.body["scimType"], "mutability");
    assert_eq!(
        call(&gw.app, "GET", &format!("/Users/{id}"), &token, None)
            .await?
            .status,
        StatusCode::OK
    );
    let all = records(&gw)?;
    assert!(
        all.iter()
            .any(|r| r["action"] == "member_removed" && r["code"] == "last_owner")
    );
    Ok(())
}

#[tokio::test]
async fn scim_people_set_a_password_by_a_one_time_link() -> Result<(), Error> {
    let Some(url) = database("scim_links").await? else {
        return Ok(());
    };
    let gw = gateway("scim_links", &url, &licensed(&["members", "scim"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let token = new_token(&gw, &mut owner).await?;
    let email = "sam@example.com";
    let made = call(
        &gw.app,
        "POST",
        "/Users",
        &token,
        Some(okta_user(email, "Sam", "Scim")),
    )
    .await?;
    let id = made.body["id"].as_str().ok_or("no id")?.to_string();

    let page = owner.go(&gw.app, "GET", "/console/scim", &[]).await?;
    assert!(page.text.contains(email), "{}", page.text);
    let linked = owner
        .go(
            &gw.app,
            "POST",
            "/console/scim/password-link",
            &[("user_id", &id)],
        )
        .await?;
    assert_eq!(linked.status, StatusCode::OK);
    let link = linked
        .text
        .split("/console/set-password/")
        .nth(1)
        .map(|rest| {
            rest.chars()
                .take_while(char::is_ascii_hexdigit)
                .collect::<String>()
        })
        .filter(|t| t.len() == 64)
        .ok_or(linked.text)?;
    let nobody = owner
        .go(
            &gw.app,
            "POST",
            "/console/scim/password-link",
            &[("user_id", "usr_nobody")],
        )
        .await?;
    assert!(
        nobody.text.contains("No link created") && !nobody.text.contains("/console/set-password/")
    );

    let mut person = Browser::default();
    let path = format!("/console/set-password/{link}");
    assert_eq!(
        person.go(&gw.app, "GET", &path, &[]).await?.status,
        StatusCode::OK
    );
    let short = person
        .go(&gw.app, "POST", &path, &[("password", "short")])
        .await?;
    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    let set = person
        .go(
            &gw.app,
            "POST",
            &path,
            &[("password", "a-brand-new-password")],
        )
        .await?;
    assert_eq!(set.status, StatusCode::SEE_OTHER, "{}", set.text);
    assert!(!person.cookie.is_empty());
    let twice = Browser::default()
        .go(
            &gw.app,
            "POST",
            &path,
            &[("password", "another-password-1")],
        )
        .await?;
    assert_eq!(twice.status, StatusCode::GONE);
    let signin = Browser::default()
        .go(
            &gw.app,
            "POST",
            "/console/sign-in/password",
            &[("email", email), ("password", "a-brand-new-password")],
        )
        .await?;
    assert_eq!(signin.status, StatusCode::SEE_OTHER);
    let second = owner
        .go(
            &gw.app,
            "POST",
            "/console/scim/password-link",
            &[("user_id", &id)],
        )
        .await?;
    assert!(second.text.contains("No link created"));
    let all = records(&gw)?;
    record(&all, "password_link_created")?;
    record(&all, "password_set_by_link")?;
    Ok(())
}

#[tokio::test]
async fn tokens_are_made_by_an_owner_shown_once_and_kept_hashed() -> Result<(), Error> {
    let Some(url) = database("scim_tokens").await? else {
        return Ok(());
    };
    let gw = gateway("scim_tokens", &url, &licensed(&["members", "scim"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let token = new_token(&gw, &mut owner).await?;
    let page = owner.go(&gw.app, "GET", "/console/scim", &[]).await?;
    assert!(token_in(&page.text).is_none(), "the token is shown again");
    assert!(page.text.contains("/console/scim/v2"));
    let stored: Vec<String> = client(&url)
        .await?
        .query("SELECT token_sha256 FROM enterprise_scim_tokens", &[])
        .await?
        .iter()
        .filter_map(|r| r.try_get(0).ok())
        .collect();
    assert_eq!(stored, [enterplace_core::id::sha256_hex(token.as_bytes())]);

    // An admin who is not an owner cannot make one.
    let made = call(
        &gw.app,
        "POST",
        "/Users",
        &token,
        Some(okta_user("adm@example.com", "A", "Dm")),
    )
    .await?;
    let id = made.body["id"].as_str().ok_or("no id")?.to_string();
    owner
        .go(
            &gw.app,
            "POST",
            "/console/members/role",
            &[("user_id", &id), ("role", "admin"), ("team", "default")],
        )
        .await?;
    let linked = owner
        .go(
            &gw.app,
            "POST",
            "/console/scim/password-link",
            &[("user_id", &id)],
        )
        .await?;
    let link = linked
        .text
        .split("/console/set-password/")
        .nth(1)
        .map(|r| r.chars().take(64).collect::<String>())
        .ok_or("no link")?;
    let mut admin = Browser::default();
    admin
        .go(
            &gw.app,
            "POST",
            &format!("/console/set-password/{link}"),
            &[("password", "admin-password-123")],
        )
        .await?;
    let tried = admin
        .go(&gw.app, "POST", "/console/scim/tokens", &[("name", "x")])
        .await?;
    assert!(
        tried.text.contains("Only an owner") && token_in(&tried.text).is_none(),
        "{}",
        tried.text
    );

    // Revoked, it stops working at once.
    let prefix = &stored[0][..16];
    let revoked = owner
        .go(
            &gw.app,
            "POST",
            "/console/scim/tokens/revoke",
            &[("prefix", prefix)],
        )
        .await?;
    assert_eq!(revoked.status, StatusCode::SEE_OTHER, "{}", revoked.text);
    assert_eq!(
        call(&gw.app, "GET", "/Users", &token, None).await?.status,
        StatusCode::UNAUTHORIZED
    );
    let all = records(&gw)?;
    record(&all, "scim_token_created")?;
    record(&all, "scim_token_revoked")?;
    assert!(!std::fs::read_to_string(gw.dir.join("enterplace-audit.jsonl"))?.contains(&token));
    Ok(())
}

#[tokio::test]
async fn guessing_tokens_is_rate_limited() -> Result<(), Error> {
    let Some(url) = database("scim_rate").await? else {
        return Ok(());
    };
    let gw = gateway("scim_rate", &url, &licensed(&["members", "scim"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let token = new_token(&gw, &mut owner).await?;
    for _ in 0..BAD_TOKENS_PER_MINUTE {
        let wrong = call(&gw.app, "GET", "/Users", "gscim_wrong", None).await?;
        assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    }
    // Past the limit even the right token waits: the address is the one guessing.
    let limited = call(&gw.app, "GET", "/Users", &token, None).await?;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.body["status"], "429");
    Ok(())
}

#[tokio::test]
async fn without_the_feature_scim_answers_license_required() -> Result<(), Error> {
    for (name, status) in [
        ("none", unlicensed()),
        ("members_only", licensed(&["members"])),
        ("scim_only", licensed(&["scim"])),
    ] {
        let test = format!("scim_gate_{name}");
        let Some(url) = database(&test).await? else {
            return Ok(());
        };
        let gw = gateway(&test, &url, &status)?;
        let mut admin = Browser::admin(&gw.app).await?;
        let audit = admin.go(&gw.app, "GET", "/console/audit", &[]).await?;
        assert!(
            !audit.text.contains(r#"href="/console/scim""#),
            "{name}: nav entry"
        );
        let page = admin.go(&gw.app, "GET", "/console/scim", &[]).await?;
        assert_eq!(page.status, StatusCode::FORBIDDEN, "{name}");
        assert!(
            page.text.contains("license_required"),
            "{name}: {}",
            page.text
        );
        let made = admin
            .go(&gw.app, "POST", "/console/scim/tokens", &[("name", "x")])
            .await?;
        assert!(token_in(&made.text).is_none(), "{name}: a token was made");
        let api = call(&gw.app, "GET", "/Users", "gscim_any", None).await?;
        assert_eq!(api.status, StatusCode::FORBIDDEN, "{name}");
        assert_eq!(api.content_type, "application/scim+json");
        assert!(
            api.body["detail"]
                .as_str()
                .is_some_and(|d| d.contains("license")),
            "{name}"
        );
        // SCIM's tables and column are made only when it is on; members' only when members is.
        let db = client(&url).await?;
        let scim: i64 = db
            .query_one("SELECT count(*) FROM information_schema.columns WHERE table_name LIKE 'enterprise_%' AND (table_name LIKE 'enterprise_scim_%' OR table_name = 'enterprise_password_links' OR column_name = 'scim_external_id')", &[])
            .await?
            .try_get(0)?;
        assert_eq!(scim, 0, "{name}");
        let people: i64 = db
            .query_one("SELECT count(*) FROM information_schema.tables WHERE table_name = 'enterprise_people'", &[])
            .await?
            .try_get(0)?;
        assert_eq!(people, i64::from(name == "members_only"), "{name}");
    }
    Ok(())
}
