//! Identity headers end to end, over real connections so the gateway sees a peer address: from a trusted proxy the
//! headers name the caller on the model routes and in the console; from anywhere else, and without the license
//! feature, they are ignored.

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::enterprise::testing::*;

const SETTING: &str = "identity_headers: { user: X-Forwarded-User, groups: X-Forwarded-Groups }\nteams:\n  - name: engineering\n    sso_values: [eng]\nroles:\n  - name: auditors\n    permissions: [see_keys, see_records]\n    sso_values: [enterplace-auditors]\n";

struct Reply {
    status: u16,
    text: String,
}

/// One request over a connection from 127.0.0.1, with `headers` as an authenticating proxy (or anyone) writes them.
async fn get(
    addr: std::net::SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<Reply, Error> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request += &format!("{name}: {value}\r\n");
    }
    stream.write_all((request + "\r\n").as_bytes()).await?;
    let mut text = String::new();
    stream.read_to_string(&mut text).await?;
    let status = text
        .get(9..12)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("no status in {text}"))?;
    Ok(Reply { status, text })
}

/// A gateway that trusts `proxies`, listening on a port of this machine.
async fn listening(
    test: &str,
    url: &str,
    status: &crate::license::Status,
    proxies: &str,
) -> Result<(Gateway, std::net::SocketAddr), Error> {
    let policy = format!("{POLICY}trusted_proxies: [{proxies}]\n{SETTING}");
    let gw = gateway_policy(test, url, status, &[], &policy)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(enterplace_server::serve_on(
        listener,
        gw.app.clone(),
        enterplace_server::Config::default().timeouts,
        std::future::pending(),
    ));
    Ok((gw, addr))
}

const MAYA: (&str, &str) = ("X-Forwarded-User", "Maya@Example.com");

#[tokio::test]
async fn a_trusted_proxy_names_the_caller_on_the_model_routes_and_in_the_console()
-> Result<(), Error> {
    let Some(url) = database("auth_proxy_trusted").await? else {
        return Ok(());
    };
    let (gw, addr) = listening(
        "auth_proxy_trusted",
        &url,
        &licensed(&["auth_proxy"]),
        "127.0.0.1",
    )
    .await?;

    // No key: the proxy's headers say who is asking, and their group puts them in a team.
    let models = get(
        addr,
        "/v1/models",
        &[MAYA, ("X-Forwarded-Groups", "everyone, eng")],
    )
    .await?;
    assert_eq!(models.status, 200, "{}", models.text);
    // Nothing on the request: refused as any request with no key.
    let none = get(addr, "/v1/models", &[]).await?;
    assert_eq!(none.status, 401);
    assert!(none.text.contains("no_key"), "{}", none.text);
    // The header twice: one value is not the proxy's, so neither is taken.
    let twice = get(
        addr,
        "/v1/models",
        &[
            MAYA,
            ("X-Forwarded-User", "root@example.com"),
            ("X-Forwarded-Groups", "eng"),
        ],
    )
    .await?;
    assert_eq!(twice.status, 401);
    assert!(
        twice.text.contains("identity_invalid") && twice.text.contains("more than once"),
        "{}",
        twice.text
    );
    // A person no team takes is refused, by name.
    let no_team = get(addr, "/v1/models", &[MAYA, ("X-Forwarded-Groups", "sales")]).await?;
    assert_eq!(no_team.status, 401);
    assert!(no_team.text.contains("is in no team"), "{}", no_team.text);
    // An Enterplace key beside the headers is the caller: the key decides.
    let auth = format!("Bearer {ADMIN_KEY}");
    let keyed = get(addr, "/v1/models", &[MAYA, ("Authorization", &auth)]).await?;
    assert_eq!(keyed.status, 200, "{}", keyed.text);

    // The console: the group of a role signs the person in with it, and no role is no console.
    let auditor = get(
        addr,
        "/console/api/me",
        &[MAYA, ("X-Forwarded-Groups", "enterplace-auditors")],
    )
    .await?;
    assert_eq!(auditor.status, 200, "{}", auditor.text);
    assert!(
        auditor.text.contains("maya@example.com") && auditor.text.contains("auditor"),
        "{}",
        auditor.text
    );
    let engineer = get(
        addr,
        "/console/api/me",
        &[MAYA, ("X-Forwarded-Groups", "eng")],
    )
    .await?;
    assert_eq!(
        engineer.status, 401,
        "a team is not a console role: {}",
        engineer.text
    );

    gw.log.flush();
    let log = std::fs::read_to_string(&gw.audit)?;
    let records: Vec<Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let allowed: Vec<&Value> = records
        .iter()
        .filter(|r| r["path"] == "/v1/models" && r["verdict"] == "allow")
        .collect();
    assert_eq!(allowed.len(), 2, "{log}");
    assert_eq!(allowed[0]["person"], "maya@example.com");
    assert_eq!(allowed[0]["team"], "engineering");
    assert_eq!(allowed[0]["auth"], "identity_headers");
    assert_eq!(allowed[1]["person"], "noa");
    assert!(allowed[1].get("auth").is_none(), "{log}");
    Ok(())
}

#[tokio::test]
async fn headers_from_anywhere_but_a_trusted_proxy_are_ignored() -> Result<(), Error> {
    let Some(url) = database("auth_proxy_untrusted").await? else {
        return Ok(());
    };
    // The policy trusts another network: this machine's connections are a stranger's.
    let (_gw, addr) = listening(
        "auth_proxy_untrusted",
        &url,
        &licensed(&["auth_proxy"]),
        "10.0.0.0/8",
    )
    .await?;
    let models = get(addr, "/v1/models", &[MAYA, ("X-Forwarded-Groups", "eng")]).await?;
    assert_eq!(models.status, 401);
    assert!(models.text.contains("no_key"), "{}", models.text);
    let console = get(
        addr,
        "/console/audit",
        &[MAYA, ("X-Forwarded-Groups", "enterplace-auditors")],
    )
    .await?;
    assert_eq!(console.status, 303, "{}", console.text);
    // A forged X-Forwarded-For does not make a stranger a proxy.
    let forged = get(
        addr,
        "/v1/models",
        &[
            MAYA,
            ("X-Forwarded-Groups", "eng"),
            ("X-Forwarded-For", "10.0.0.5"),
        ],
    )
    .await?;
    assert_eq!(forged.status, 401);
    Ok(())
}

#[tokio::test]
async fn without_the_license_feature_the_headers_are_not_read() -> Result<(), Error> {
    for (n, status) in [unlicensed(), licensed(&["members", "devices"])]
        .iter()
        .enumerate()
    {
        // A database each: both gateways seed the same keys.
        let Some(url) = database(&format!("auth_proxy_locked{n}")).await? else {
            return Ok(());
        };
        let (_gw, addr) =
            listening(&format!("auth_proxy_locked{n}"), &url, status, "127.0.0.1").await?;
        let models = get(addr, "/v1/models", &[MAYA, ("X-Forwarded-Groups", "eng")]).await?;
        assert_eq!(models.status, 401);
        assert!(models.text.contains("no_key"), "{}", models.text);
        let console = get(
            addr,
            "/console/audit",
            &[MAYA, ("X-Forwarded-Groups", "enterplace-auditors")],
        )
        .await?;
        assert_eq!(console.status, 303, "{}", console.text);
    }
    Ok(())
}
