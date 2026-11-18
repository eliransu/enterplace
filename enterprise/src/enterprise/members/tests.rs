//! The members behaviour of the Cloudflare app (cloud/tests/test_members.py and test_members_links.py), against a
//! real Postgres, plus the license gate. SCIM and the password links for people SCIM makes are tested in
//! `scim/tests.rs`; the admin API's add member has no counterpart in a one-org install.

use axum::http::StatusCode;

use super::*;
use crate::enterprise::testing::*;

/// The ID in the members list of the row that shows `email`.
fn user_id_in(page: &str, email: &str) -> Option<String> {
    page.split(r#"<div class="g-row">"#)
        .find(|row| row.contains(email))
        .and_then(|row| row.split(r#"name="user_id" value=""#).nth(1))
        .and_then(|rest| rest.split('"').next())
        .map(str::to_string)
}

/// The token of the invite link on a page.
fn invite_token(page: &str) -> Option<String> {
    let rest = page.split("/console/invite/").nth(1)?;
    let token: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
    (token.len() == 48).then_some(token)
}

/// Invites `email` and has them accept as `name`: their browser, signed in.
async fn join(
    gw: &Gateway,
    by: &mut Browser,
    email: &str,
    role: &str,
    team: &str,
) -> Result<Browser, Error> {
    let made = by
        .go(
            &gw.app,
            "POST",
            "/console/members/invite",
            &[("email", email), ("role", role), ("team", team)],
        )
        .await?;
    let token = invite_token(&made.text).ok_or(format!("no invite link: {}", made.text))?;
    let mut person = Browser::default();
    let joined = person
        .go(
            &gw.app,
            "POST",
            &format!("/console/invite/{token}"),
            &[("name", "Sam Second"), ("password", "second-password-123")],
        )
        .await?;
    if joined.status != StatusCode::SEE_OTHER || person.cookie.is_empty() {
        return Err(format!("accept: {} {}", joined.status, joined.text).into());
    }
    Ok(person)
}

#[test]
fn passwords_hash_as_the_cloudflare_app_hashes_them() -> Result<(), String> {
    // PBKDF2-SHA256, 100,000 iterations, the salt as hex bytes, as cloud/control-plane/src/lib/crypto.ts does.
    let hash = enterplace_core::id::hex(&derive(
        "owner-password-123",
        &unhex("00112233445566778899aabbccddeeff").ok_or("salt")?,
    ));
    assert_eq!(
        hash,
        "13ccc2a43687e5fd9cedfc6ef806ab2104f0a1dc1eea3ca672d4eef78d2cbcf6"
    );
    let (salt, hash) = hash_password("a-long-password")?;
    assert_eq!(salt.len(), 32);
    assert!(password_matches("a-long-password", &salt, &hash));
    assert!(!password_matches("a-long-passwore", &salt, &hash));
    // A person with no password yet (SCIM writes "!") matches nothing.
    assert!(!password_matches("", &salt, "!"));
    Ok(())
}

#[test]
fn emails_and_teams_are_checked_as_the_cloudflare_app_checks_them() {
    for ok in ["a@b.co", "first.last+x@example.com"] {
        assert!(valid_email(ok), "{ok}");
    }
    for bad in ["", "a@b", "@b.co", "a b@c.co", "a@b@c.co"] {
        assert!(!valid_email(bad), "{bad}");
    }
    assert!(valid_team("research.ops_1-a"));
    assert!(!valid_team("") && !valid_team("a b") && !valid_team(&"a".repeat(65)));
}

#[tokio::test]
async fn invite_accept_roles_and_the_last_owner() -> Result<(), Error> {
    let Some(url) = database("members").await? else {
        return Ok(());
    };
    let gw = gateway("members", &url, &licensed(&["members"]))?;
    let second_email = "second@example.com";
    let mut owner = Browser::admin(&gw.app).await?;

    // A key for the second person, by email, before they join.
    enterplace_core::keyfile::add_entry(
        second_email,
        "research",
        "enterplace_second_0123456789abcdef01234567",
        false,
        &gw.keys,
    )?;

    // Invite: the link is shown once, and the page for it shows the role and a sign-up form.
    let made = owner
        .go(
            &gw.app,
            "POST",
            "/console/members/invite",
            &[
                ("email", second_email),
                ("role", "viewer"),
                ("team", "research"),
            ],
        )
        .await?;
    assert_eq!(made.status, StatusCode::OK);
    let token = invite_token(&made.text).ok_or(made.text)?;
    let mut second = Browser::default();
    let page = second
        .go(&gw.app, "GET", &format!("/console/invite/{token}"), &[])
        .await?;
    assert!(
        page.status == StatusCode::OK
            && page.text.contains("viewer")
            && page.text.contains(r#"name="password""#),
        "{}",
        page.text
    );
    // A short password is refused, and the invite stays open.
    let short = second
        .go(
            &gw.app,
            "POST",
            &format!("/console/invite/{token}"),
            &[("name", "Sam"), ("password", "short")],
        )
        .await?;
    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    assert!(short.text.contains("12 characters"));
    let joined = second
        .go(
            &gw.app,
            "POST",
            &format!("/console/invite/{token}"),
            &[("name", "Sam Second"), ("password", "second-password-123")],
        )
        .await?;
    assert_eq!(joined.status, StatusCode::SEE_OTHER, "{}", joined.text);
    assert_eq!(joined.location, "/console/start");
    assert!(!second.cookie.is_empty(), "the new member is not signed in");
    let used = Browser::default()
        .go(&gw.app, "GET", &format!("/console/invite/{token}"), &[])
        .await?;
    assert!(
        used.status == StatusCode::GONE && used.text.contains("already"),
        "{}",
        used.text
    );
    let again = Browser::default()
        .go(
            &gw.app,
            "POST",
            &format!("/console/invite/{token}"),
            &[("name", "Eve"), ("password", "eve-password-1234")],
        )
        .await?;
    assert_eq!(
        again.status,
        StatusCode::GONE,
        "a used invite was accepted twice"
    );

    // The new member sees the members page, and the nav entry on every page.
    let list = second.go(&gw.app, "GET", "/console/members", &[]).await?;
    assert!(
        list.status == StatusCode::OK && list.text.contains(second_email),
        "{}",
        list.text
    );
    assert!(
        list.text
            .contains(r#"href="/console/members" aria-current="page">Members"#)
    );
    let audit = second.go(&gw.app, "GET", "/console/start", &[]).await?;
    assert_eq!(audit.status, StatusCode::OK);
    assert!(audit.text.contains("second@example.com") && audit.text.contains("viewer"));

    // Roles. A viewer changes nothing.
    let page = owner.go(&gw.app, "GET", "/console/members", &[]).await?;
    let second_id = user_id_in(&page.text, second_email).ok_or(page.text.clone())?;
    let refused = second
        .go(
            &gw.app,
            "POST",
            "/console/members/role",
            &[
                ("user_id", &second_id),
                ("role", "admin"),
                ("team", "default"),
            ],
        )
        .await?;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let made_admin = owner
        .go(
            &gw.app,
            "POST",
            "/console/members/role",
            &[
                ("user_id", &second_id),
                ("role", "admin"),
                ("team", "research"),
            ],
        )
        .await?;
    assert_eq!(made_admin.status, StatusCode::SEE_OTHER);
    let page = owner.go(&gw.app, "GET", "/console/members", &[]).await?;
    let row = page
        .text
        .split(r#"<div class="g-row">"#)
        .find(|r| r.contains(second_email))
        .unwrap_or("");
    assert!(row.contains(r#"<option value="admin" selected"#), "{row}");
    // The session follows the role at once: no sign-in again.
    let audit = second.go(&gw.app, "GET", "/console/start", &[]).await?;
    assert!(audit.text.contains("admin"));
    // An admin cannot make an owner.
    let refused = second
        .go(
            &gw.app,
            "POST",
            "/console/members/role",
            &[
                ("user_id", &second_id),
                ("role", "owner"),
                ("team", "research"),
            ],
        )
        .await?;
    assert!(refused.text.contains("Only an owner"), "{}", refused.text);
    // The admin key acts as an owner: it makes the second person the one owner.
    owner
        .go(
            &gw.app,
            "POST",
            "/console/members/role",
            &[
                ("user_id", &second_id),
                ("role", "owner"),
                ("team", "research"),
            ],
        )
        .await?;
    let removed = owner
        .go(
            &gw.app,
            "POST",
            "/console/members/remove",
            &[("user_id", &second_id)],
        )
        .await?;
    assert!(
        removed.status == StatusCode::CONFLICT && removed.text.contains("last owner"),
        "{}",
        removed.text
    );
    let demoted = owner
        .go(
            &gw.app,
            "POST",
            "/console/members/role",
            &[
                ("user_id", &second_id),
                ("role", "admin"),
                ("team", "admins"),
            ],
        )
        .await?;
    assert!(
        demoted.status == StatusCode::OK && demoted.text.contains("last owner"),
        "{}",
        demoted.text
    );

    // Every change is in the audit log, in the gateway's chain.
    let log = std::fs::read_to_string(gw.dir.join("enterplace-audit.jsonl"))?;
    for action in ["invite_created", "invite_accepted", "member_changed"] {
        assert!(
            log.contains(&format!(r#""action":"{action}""#)),
            "{action} not recorded"
        );
    }
    Ok(())
}

#[tokio::test]
async fn removing_a_person_revokes_their_keys_and_ends_their_session() -> Result<(), Error> {
    let Some(url) = database("remove").await? else {
        return Ok(());
    };
    let gw = gateway("remove", &url, &licensed(&["all"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let email = "leaver@example.com";
    let mut leaver = join(&gw, &mut owner, email, "admin", "ops").await?;
    // Two keys named with their email (one in another case) and one of someone else's.
    enterplace_core::keyfile::add_entry(
        email,
        "ops",
        "enterplace_leaver1_0123456789abcdef012345678",
        false,
        &gw.keys,
    )?;
    enterplace_core::keyfile::add_entry(
        "Leaver@Example.com",
        "ops",
        "enterplace_leaver2_0123456789abcdef012345678",
        false,
        &gw.keys,
    )?;
    enterplace_core::keyfile::add_entry(
        "stays@example.com",
        "ops",
        "enterplace_stays_0123456789abcdef01234567890",
        false,
        &gw.keys,
    )?;
    let page = owner.go(&gw.app, "GET", "/console/members", &[]).await?;
    let id = user_id_in(&page.text, email).ok_or(page.text)?;
    let removed = owner
        .go(
            &gw.app,
            "POST",
            "/console/members/remove",
            &[("user_id", &id)],
        )
        .await?;
    assert_eq!(removed.status, StatusCode::SEE_OTHER, "{}", removed.text);
    let keys = enterplace_core::config::read_keys(&gw.keys)?.unwrap_or_default();
    assert!(!keys.to_lowercase().contains(email), "{keys}");
    assert!(keys.contains("stays@example.com"));
    // Their session ends at once, and they cannot sign in again.
    let after = leaver.go(&gw.app, "GET", "/console/members", &[]).await?;
    assert_eq!(after.status, StatusCode::SEE_OTHER);
    let again = Browser::default()
        .go(
            &gw.app,
            "POST",
            "/console/sign-in/password",
            &[("email", email), ("password", "second-password-123")],
        )
        .await?;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    let log = std::fs::read_to_string(gw.dir.join("enterplace-audit.jsonl"))?;
    let record = log
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|r| r["action"] == "member_removed")
        .ok_or("member_removed not recorded")?;
    assert_eq!(
        record["target"]["keys_revoked"].as_array().map(Vec::len),
        Some(2)
    );
    Ok(())
}

#[tokio::test]
async fn invited_people_sign_in_with_their_password() -> Result<(), Error> {
    let Some(url) = database("password").await? else {
        return Ok(());
    };
    let gw = gateway("password", &url, &licensed(&["members"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    join(&gw, &mut owner, "ada@example.com", "viewer", "default").await?;
    // The sign-in page offers the way in.
    let page = Browser::default()
        .go(&gw.app, "GET", "/console/sign-in", &[])
        .await?;
    assert!(
        page.text.contains(r#"href="/console/sign-in/password""#),
        "{}",
        page.text
    );
    // A wrong password and an unknown email get the same answer.
    let wrong = Browser::default()
        .go(
            &gw.app,
            "POST",
            "/console/sign-in/password",
            &[
                ("email", "ada@example.com"),
                ("password", "not-the-password"),
            ],
        )
        .await?;
    let unknown = Browser::default()
        .go(
            &gw.app,
            "POST",
            "/console/sign-in/password",
            &[
                ("email", "nobody@example.com"),
                ("password", "not-the-password"),
            ],
        )
        .await?;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert!(wrong.text.contains("do not match") && unknown.text.contains("do not match"));
    let mut ada = Browser::default();
    let signed = ada
        .go(
            &gw.app,
            "POST",
            "/console/sign-in/password",
            &[
                ("email", "Ada@Example.com"),
                ("password", "second-password-123"),
            ],
        )
        .await?;
    assert_eq!(signed.status, StatusCode::SEE_OTHER);
    assert_eq!(signed.location, "/console/start");
    // A viewer may look and may not issue keys.
    let audit = ada.go(&gw.app, "GET", "/console/start", &[]).await?;
    assert_eq!(audit.status, StatusCode::OK);
    let issue = ada
        .go(
            &gw.app,
            "POST",
            "/console/api/people/issue",
            &[("name", "x"), ("team", "y")],
        )
        .await?;
    assert_eq!(issue.status, StatusCode::FORBIDDEN);
    // A form from another site is refused.
    let foreign = axum::http::Request::post("/console/sign-in/password")
        .header("host", HOST)
        .header("origin", "https://evil.example")
        .body(axum::body::Body::from(
            "email=ada%40example.com&password=second-password-123",
        ))?;
    let answer = tower::ServiceExt::oneshot(gw.app.clone(), foreign).await?;
    assert_eq!(answer.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn a_revoked_invite_link_no_longer_works() -> Result<(), Error> {
    let Some(url) = database("revoke_invite").await? else {
        return Ok(());
    };
    let gw = gateway("revoke_invite", &url, &licensed(&["members"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let made = owner
        .go(
            &gw.app,
            "POST",
            "/console/members/invite",
            &[
                ("email", "invitee@example.com"),
                ("role", "viewer"),
                ("team", "default"),
            ],
        )
        .await?;
    let token = invite_token(&made.text).ok_or(made.text)?;
    let page = owner.go(&gw.app, "GET", "/console/members", &[]).await?;
    let prefix = page
        .text
        .split(r#"name="prefix" value=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .ok_or("pending invite has no revoke button")?
        .to_string();
    assert_eq!(prefix.len(), 16);
    let revoked = owner
        .go(
            &gw.app,
            "POST",
            "/console/members/invite/revoke",
            &[("prefix", &prefix)],
        )
        .await?;
    assert!(
        revoked.status == StatusCode::OK && revoked.text.contains("Invite revoked"),
        "{}",
        revoked.text
    );
    let link = Browser::default()
        .go(&gw.app, "GET", &format!("/console/invite/{token}"), &[])
        .await?;
    assert!(matches!(
        link.status,
        StatusCode::NOT_FOUND | StatusCode::GONE
    ));
    // Someone who is already a member gets no second invite.
    join(&gw, &mut owner, "member@example.com", "viewer", "default").await?;
    let twice = owner
        .go(
            &gw.app,
            "POST",
            "/console/members/invite",
            &[
                ("email", "member@example.com"),
                ("role", "viewer"),
                ("team", "default"),
            ],
        )
        .await?;
    assert!(twice.text.contains("already a member") && invite_token(&twice.text).is_none());
    Ok(())
}

#[tokio::test]
async fn without_the_feature_the_console_keeps_admin_keys_only() -> Result<(), Error> {
    // Every other feature, alone, makes none of members' tables: each runs its own migrations only. SCIM without
    // members is off, since it keeps the people members does.
    for (name, status) in [
        ("none", unlicensed()),
        ("siem", licensed(&["siem"])),
        ("retention", licensed(&["retention"])),
        ("scim", licensed(&["scim"])),
        ("reports", licensed(&["reports"])),
    ] {
        let test = format!("gate_{name}");
        let Some(url) = database(&test).await? else {
            return Ok(());
        };
        let gw = gateway(&test, &url, &status)?;
        let signin = Browser::default()
            .go(&gw.app, "GET", "/console/sign-in", &[])
            .await?;
        assert!(!signin.text.contains("/console/sign-in/password"), "{name}");
        let mut admin = Browser::admin(&gw.app).await?;
        let audit = admin.go(&gw.app, "GET", "/console/start", &[]).await?;
        assert!(
            !audit.text.contains(r#"href="/console/members""#),
            "{name}: nav entry"
        );
        let members = admin.go(&gw.app, "GET", "/console/members", &[]).await?;
        assert_eq!(members.status, StatusCode::FORBIDDEN, "{name}");
        assert!(
            members.text.contains("license_required"),
            "{name}: {}",
            members.text
        );
        let form = admin
            .go(
                &gw.app,
                "POST",
                "/console/members/invite",
                &[("email", "a@b.co"), ("role", "viewer")],
            )
            .await?;
        assert_ne!(
            form.status,
            StatusCode::OK,
            "{name}: an invite was made without the feature"
        );
        // None of members' tables were made, and no other feature's when nothing else is unlocked.
        let config: enterplace_server::store::tokio_postgres::Config = url.parse()?;
        let (client, connection) = config
            .connect(enterplace_server::store::tokio_postgres::NoTls)
            .await?;
        tokio::spawn(connection);
        let tables: i64 = client
            .query_one("SELECT count(*) FROM information_schema.tables WHERE table_name IN ('enterprise_people', 'enterprise_invites')", &[])
            .await?
            .try_get(0)?;
        assert_eq!(tables, 0, "{name}");
        if matches!(name, "none" | "scim" | "reports") {
            let any: i64 = client
                .query_one("SELECT count(*) FROM information_schema.tables WHERE table_name LIKE 'enterprise_%'", &[])
                .await?
                .try_get(0)?;
            assert_eq!(any, 0, "{name}");
        }
    }
    Ok(())
}
