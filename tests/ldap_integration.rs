//! Real LDAP integration tests (persea#154).
//!
//! Proves the LDAP auth provider against a real OpenLDAP server instead of
//! mocks: bind + search, group resolution via the member filter,
//! anti-enumeration, user lookup, and the full login flow through the real
//! binary. Driven by env vars:
//!
//! - `TEST_LDAP_URL` — an `ldap://` URL of a seeded OpenLDAP server. Start
//!   one locally with `docker compose -f docker-compose.ldap.yml up -d`, or
//!   let the CI `ldap-integration` job provide it.
//!
//! When the env var is unset every test skips with a visible message, so
//! plain `cargo test` (no LDAP server) stays green.
//!
//! The seed data (`tests/fixtures/ldap-seed.ldif`) provides:
//! - `uid=alice,ou=users,dc=example,dc=com` (cn: Alice Example, mail:
//!   alice@example.com, password: alice-ldap-password-2026)
//! - `uid=bob,ou=users,dc=example,dc=com` (cn: Bob Example, mail:
//!   bob@example.com, password: bob-ldap-password-2026)
//! - `cn=engineers,ou=groups,dc=example,dc=com` with member alice

mod support;

use persea::auth_chain::AuthChain;
use persea::auth_provider::{AuthRequest, AuthResult};
use persea::auth_providers::ldap::{LdapConfig, LdapProvider};
use serde_json::json;
use std::time::{Duration, Instant};

const LDAP_URL_ENV: &str = "TEST_LDAP_URL";
const HEALTH_TIMEOUT: Duration = Duration::from_secs(90);

const ALICE_DN: &str = "uid=alice,ou=users,dc=example,dc=com";
const BOB_DN: &str = "uid=bob,ou=users,dc=example,dc=com";
const ALICE_PASSWORD: &str = "alice-ldap-password-2026";
const BOB_PASSWORD: &str = "bob-ldap-password-2026";

fn ldap_url() -> Option<String> {
    std::env::var(LDAP_URL_ENV).ok().filter(|u| !u.is_empty())
}

fn skip_message(test: &str) {
    eprintln!(
        "SKIPPED {test}: {LDAP_URL_ENV} is not set \
         (start the harness with `docker compose -f docker-compose.ldap.yml up -d --wait` \
         and set {LDAP_URL_ENV}=ldap://127.0.0.1:3389 to run this test)"
    );
}

/// Provider pointed at the seeded harness, with the standard `(uid={})`
/// user filter and `(member={})` group resolution.
fn make_provider(url: &str, user_filter: &str) -> LdapProvider {
    LdapProvider::new(LdapConfig {
        url: url.into(),
        bind_dn: "cn=admin,dc=example,dc=com".into(),
        bind_password: "admin".into(),
        user_search_base: "ou=users,dc=example,dc=com".into(),
        user_search_filter: user_filter.into(),
        group_search_base: Some("ou=groups,dc=example,dc=com".into()),
        group_search_filter: Some("(member={})".into()),
        tls_skip_verify: false,
        starttls: false,
        connect_timeout_secs: 10,
        display_name_attr: "cn".into(),
        email_attr: "mail".into(),
    })
}

fn chain(url: &str, user_filter: &str) -> AuthChain {
    AuthChain::new(vec![Box::new(make_provider(url, user_filter))])
}

fn auth_request(username: &str, password: &str) -> AuthRequest {
    AuthRequest {
        username: Some(username.into()),
        password: Some(password.into()),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// In-process tests against the real server
// ---------------------------------------------------------------------------

#[test]
fn valid_user_authenticates_with_groups() {
    let Some(url) = ldap_url() else {
        skip_message("valid_user_authenticates_with_groups");
        return;
    };
    let chain = chain(&url, "(uid={})");
    let result =
        futures::executor::block_on(chain.authenticate(&auth_request("alice", ALICE_PASSWORD)));
    match result {
        AuthResult::Success {
            subject,
            display_name,
            groups,
            ..
        } => {
            assert_eq!(subject, ALICE_DN, "subject must be the user DN");
            // find_user requests only the dn attribute, so authenticate
            // cannot read cn; the provider falls back to the username.
            // (lookup_user_returns_user_info covers cn resolution.)
            assert_eq!(
                display_name, "alice",
                "display name falls back to the username"
            );
            assert!(
                groups.iter().any(|g| g == "engineers"),
                "group resolution via member filter failed: {groups:?}"
            );
        }
        other => panic!("expected Success, got {other}"),
    }
}

#[test]
fn second_user_authenticates_without_groups() {
    let Some(url) = ldap_url() else {
        skip_message("second_user_authenticates_without_groups");
        return;
    };
    let chain = chain(&url, "(uid={})");
    let result =
        futures::executor::block_on(chain.authenticate(&auth_request("bob", BOB_PASSWORD)));
    match result {
        AuthResult::Success {
            subject, groups, ..
        } => {
            assert_eq!(subject, BOB_DN);
            assert!(
                groups.is_empty(),
                "bob is not a group member, got {groups:?}"
            );
        }
        other => panic!("expected Success, got {other}"),
    }
}

#[test]
fn wrong_password_fails() {
    let Some(url) = ldap_url() else {
        skip_message("wrong_password_fails");
        return;
    };
    let chain = chain(&url, "(uid={})");
    let result = futures::executor::block_on(
        chain.authenticate(&auth_request("alice", "wrong-password-2026")),
    );
    match result {
        AuthResult::Failure(msg) => assert_eq!(msg, "no provider could authenticate"),
        other => panic!("expected Failure, got {other}"),
    }
}

#[test]
fn unknown_user_fails_identically() {
    let Some(url) = ldap_url() else {
        skip_message("unknown_user_fails_identically");
        return;
    };
    let chain = chain(&url, "(uid={})");
    let result = futures::executor::block_on(
        chain.authenticate(&auth_request("carol", "any-password-2026")),
    );
    match result {
        // Anti-enumeration: an unknown user must produce the exact same
        // failure as a wrong password, so the search cannot be used as a
        // username oracle.
        AuthResult::Failure(msg) => assert_eq!(msg, "no provider could authenticate"),
        other => panic!("expected Failure, got {other}"),
    }
}

#[test]
fn ambiguous_filter_fails_closed() {
    let Some(url) = ldap_url() else {
        skip_message("ambiguous_filter_fails_closed");
        return;
    };
    // (|(uid={})(uid=bob)) matches alice AND bob when the username is alice.
    let chain = chain(&url, "(|(uid={})(uid=bob))");
    let result =
        futures::executor::block_on(chain.authenticate(&auth_request("alice", ALICE_PASSWORD)));
    match result {
        AuthResult::Failure(msg) => assert_eq!(msg, "no provider could authenticate"),
        other => panic!("expected Failure, got {other}"),
    }
}

#[test]
fn lookup_user_returns_user_info() {
    let Some(url) = ldap_url() else {
        skip_message("lookup_user_returns_user_info");
        return;
    };
    // lookup_user does a base-scope search on the subject DN with the
    // configured user filter, so the filter must match the entry at that DN.
    // The standard (uid={}) filter is built for subtree username searches
    // and cannot match a DN subject; (objectClass=inetOrgPerson) matches the
    // entry at the base, which is what the lookup path needs.
    let chain = chain(&url, "(objectClass=inetOrgPerson)");
    let info = futures::executor::block_on(chain.lookup_user(ALICE_DN))
        .expect("lookup_user returned None");
    assert_eq!(info.subject, ALICE_DN);
    assert_eq!(info.display_name, "Alice Example");
    assert_eq!(info.email.as_deref(), Some("alice@example.com"));
    assert!(
        info.groups.iter().any(|g| g == "engineers"),
        "lookup group resolution failed: {:?}",
        info.groups
    );
}

// ---------------------------------------------------------------------------
// Full-stack tests: real binary, real LDAP, real login form
//
// The local accounts for these tests are created with the REAL email
// (alice@example.com), never the DN: the login handler resolves the
// local user by email, and an LDAP subject is the user DN, so a
// successful login proves the chain-lookup fallback resolves the DN to
// the account (persea#236).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_stack_login_via_http() {
    let Some(url) = ldap_url() else {
        skip_message("full_stack_login_via_http");
        return;
    };

    let marker = format!("ldap-it-{}", std::process::id());
    let tmp = std::env::temp_dir().join(&marker);
    std::fs::create_dir_all(&tmp).expect("create scratch dir");
    let config_path = tmp.join("config.toml");
    let log_path = tmp.join("persea.log");
    let db_path = tmp.join("admin.db").display().to_string();
    // The chain fallback in the login handler asks the LDAP provider to
    // resolve the DN subject to the entry's email; that lookup is a
    // base-scope search on the subject DN with the configured filter, so
    // the filter must match alice's entry at her own DN. `(uid=alice)`
    // matches at any scope; the chain-level tests above cover `{}`
    // username substitution separately.
    let write_config = |port: u16| {
        format!(
            "listen_addr = \"127.0.0.1:{port}\"\ndb_path = \"{db_path}\"\n\
             [auth]\nmethods = [\"ldap\"]\n\
             [auth.ldap]\nurl = \"{url}\"\n\
             bind_dn = \"cn=admin,dc=example,dc=com\"\nbind_password = \"admin\"\n\
             user_search_base = \"ou=users,dc=example,dc=com\"\nuser_search_filter = \"(uid=alice)\"\n\
             group_search_base = \"ou=groups,dc=example,dc=com\"\ngroup_search_filter = \"(member={{}})\"\n\
             [storage]\nencryption_key = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\n"
        )
    };

    let booted = support::boot_persea(
        "ldap-ci-admin",
        &config_path,
        &log_path,
        None,
        HEALTH_TIMEOUT,
        &write_config,
    )
    .await;
    let client = booted.client;
    let base = booted.base;
    let key = booted.key;
    let mut app = booted.app;

    // Fresh client without idle connection pooling: the booted client's
    // keep-alive connection may be closed by the server between requests,
    // which surfaces as hyper IncompleteMessage on the next send.
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .expect("build login client");

    // The login handler resolves the local user by email; the LDAP
    // subject is the user DN, so the local account is created with the
    // REAL email, not the DN: the direct email lookup misses and the
    // chain lookup must resolve the DN to this account, or the login
    // redirects to user_lookup_failed (persea#236).
    let csrf = fetch_csrf_token(&client, &base).await;
    let (status, body) = send_json(
        &client,
        reqwest::Method::POST,
        &format!("{base}/api/users"),
        &key,
        &json!({
            "email": "alice@example.com",
            "name": "Alice Example",
            "role": "viewer",
            "password": "ldap-ci-password-2026",
        }),
        Some(&csrf),
    )
    .await;
    assert_eq!(status, 201, "POST /api/users failed: {body}");

    // Wrong password: the real binary must reject with the same
    // invalid_credentials redirect a local-account failure produces.
    let resp = http
        .post(format!("{base}/auth/login"))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(reqwest::header::COOKIE, format!("csrf_token={csrf}"))
        .body(format!(
            "username=alice&password=wrong-password-2026&csrf_token={csrf}"
        ))
        .send()
        .await
        .expect("POST /auth/login (wrong password)");
    // The client follows the 303 to /?error=invalid_credentials, which
    // renders the login page; assert on the final URL.
    let final_url = resp.url().as_str().to_string();
    assert!(
        final_url.contains("error=invalid_credentials"),
        "expected invalid_credentials redirect, got {final_url}"
    );

    // Valid LDAP credentials: session cookie + redirect to connections.
    let resp = http
        .post(format!("{base}/auth/login"))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(reqwest::header::COOKIE, format!("csrf_token={csrf}"))
        .body(format!(
            "username=alice&password={ALICE_PASSWORD}&csrf_token={csrf}"
        ))
        .send()
        .await
        .expect("POST /auth/login");
    // The client follows the 303 to /connections.html with the session
    // cookie (cookies feature enabled), so the final URL is the
    // connections page.
    let final_url = resp.url().as_str().to_string();
    // Landing on /connections.html proves the session cookie was set and
    // sent on the follow (the page requires an authenticated session).
    assert!(
        final_url.ends_with("/connections.html"),
        "expected to land on /connections.html, got {final_url}"
    );

    terminate(&mut app);
    std::fs::remove_dir_all(&tmp).ok();
    eprintln!("full-stack LDAP login: PASSED");
}

/// Regression for persea#236: with a local account whose email is the
/// REAL email (not the DN), a successful LDAP login must answer with a
/// session redirect, never a `user_lookup_failed` redirect. The login
/// handler falls back to the chain lookup when the direct email lookup
/// by the DN-shaped subject misses.
#[tokio::test]
async fn ldap_login_with_real_email_account_gets_session_redirect() {
    let Some(url) = ldap_url() else {
        skip_message("ldap_login_with_real_email_account_gets_session_redirect");
        return;
    };

    let marker = format!("ldap-it-{}-lookup", std::process::id());
    let tmp = std::env::temp_dir().join(&marker);
    std::fs::create_dir_all(&tmp).expect("create scratch dir");
    let config_path = tmp.join("config.toml");
    let log_path = tmp.join("persea.log");
    let db_path = tmp.join("admin.db").display().to_string();
    // Same working filter rationale as full_stack_login_via_http: the
    // chain fallback resolves the DN subject with a base-scope search,
    // so the filter must match alice's entry at her own DN.
    let write_config = |port: u16| {
        format!(
            "listen_addr = \"127.0.0.1:{port}\"\ndb_path = \"{db_path}\"\n\
             [auth]\nmethods = [\"ldap\"]\n\
             [auth.ldap]\nurl = \"{url}\"\n\
             bind_dn = \"cn=admin,dc=example,dc=com\"\nbind_password = \"admin\"\n\
             user_search_base = \"ou=users,dc=example,dc=com\"\nuser_search_filter = \"(uid=alice)\"\n\
             group_search_base = \"ou=groups,dc=example,dc=com\"\ngroup_search_filter = \"(member={{}})\"\n\
             [storage]\nencryption_key = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\n"
        )
    };

    let booted = support::boot_persea(
        "ldap-ci-admin",
        &config_path,
        &log_path,
        None,
        HEALTH_TIMEOUT,
        &write_config,
    )
    .await;
    let client = booted.client;
    let base = booted.base;
    let key = booted.key;
    let mut app = booted.app;

    // Local account with the REAL email: the DN-shaped LDAP subject can
    // never match it directly, so the login must resolve it through the
    // chain lookup or fail with user_lookup_failed.
    let csrf = fetch_csrf_token(&client, &base).await;
    let (status, body) = send_json(
        &client,
        reqwest::Method::POST,
        &format!("{base}/api/users"),
        &key,
        &json!({
            "email": "alice@example.com",
            "name": "Alice Example",
            "role": "viewer",
            "password": "ldap-ci-password-2026",
        }),
        Some(&csrf),
    )
    .await;
    assert_eq!(status, 201, "POST /api/users failed: {body}");

    // Non-following client so the raw 303 redirect target can be
    // asserted: it must be the session redirect, not
    // /?error=user_lookup_failed.
    let no_follow = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build non-following client");
    let resp = no_follow
        .post(format!("{base}/auth/login"))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(reqwest::header::COOKIE, format!("csrf_token={csrf}"))
        .body(format!(
            "username=alice&password={ALICE_PASSWORD}&csrf_token={csrf}"
        ))
        .send()
        .await
        .expect("POST /auth/login");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SEE_OTHER,
        "LDAP login with a real-email local account must redirect (303)"
    );
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_default();
    assert!(
        !location.contains("user_lookup_failed"),
        "login must not fail user lookup, got redirect to {location}"
    );
    assert_eq!(
        location, "/connections.html",
        "expected the session redirect to /connections.html"
    );
    let has_session_cookie = resp.headers().get_all("set-cookie").iter().any(|v| {
        v.to_str()
            .map(|c| c.starts_with("persea_session="))
            .unwrap_or(false)
    });
    assert!(
        has_session_cookie,
        "login response must set the persea_session cookie"
    );

    terminate(&mut app);
    std::fs::remove_dir_all(&tmp).ok();
    eprintln!("LDAP real-email login (chain lookup): PASSED");
}

// ---------------------------------------------------------------------------
// HTTP helpers (mirror tests/backend_tests.rs)
// ---------------------------------------------------------------------------

async fn send_json(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    key: &str,
    body: &serde_json::Value,
    csrf: Option<&str>,
) -> (reqwest::StatusCode, String) {
    let mut request = client.request(method, url).bearer_auth(key).json(body);
    if let Some(tok) = csrf {
        request = request.header("X-CSRF-Token", tok);
        request = request.header("Cookie", format!("csrf_token={tok}"));
    }
    let resp = request
        .send()
        .await
        .unwrap_or_else(|e| panic!("request to {url} failed: {e}"));
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    (status, text)
}

/// Double-submit CSRF: GET the app root, capture the `csrf_token` cookie
/// value, and echo it back as `X-CSRF-Token` on state-changing requests.
async fn fetch_csrf_token(client: &reqwest::Client, base: &str) -> String {
    let resp = client
        .get(format!("{base}/"))
        .send()
        .await
        .expect("GET / for CSRF token");
    let set_cookie = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("csrf_token="))
        .unwrap_or_else(|| panic!("no csrf_token Set-Cookie in {:?}", resp.headers()));
    set_cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("csrf_token=")
        .unwrap()
        .to_string()
}

fn terminate(app: &mut support::AppProc) {
    let pid = app.child.id() as i32;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if app.child.try_wait().expect("wait on child").is_some() {
            return;
        }
        if Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = app.child.kill();
    let _ = app.child.wait();
}
