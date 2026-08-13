//! Integration tests for the desktop device-pairing flow (S04).
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::{delete, get, post};
use axum::{middleware, Extension, Router};
use persea::auth::TrustedProxies;
use persea::db::{self, Db};
use std::net::SocketAddr;
use tower::ServiceExt;

fn test_db() -> Db {
    db::init_db(std::path::Path::new(":memory:")).unwrap()
}

/// Mirror of the production wiring the dispatcher applies (main.rs:2011-2013):
/// the auth'd section stacks `CsrfLayer` then `require_auth` (auth runs
/// first); pair and status are anonymous (no auth middleware, no CSRF — the
/// ticket exempts them: no session cookie to bind, and the pairing can only
/// mint a token for a user who confirms while logged in).
fn test_router(db: Db) -> Router {
    let anon = Router::new()
        .route(
            "/api/desktop/pair",
            post(persea::api::pairing::create_pairing),
        )
        .route(
            "/api/desktop/pair/status",
            get(persea::api::pairing::pairing_status),
        );
    let authed = Router::new()
        .route(
            "/api/desktop/confirm",
            post(persea::api::pairing::confirm_pairing),
        )
        .route("/api/me/tokens", get(persea::api::tokens::list_my_tokens))
        .route(
            "/api/me/tokens/{id}",
            delete(persea::api::tokens::revoke_my_token),
        )
        .layer(persea::csrf::CsrfLayer)
        .layer(middleware::from_fn(persea::auth::require_auth));
    Router::new()
        .merge(anon)
        .merge(authed)
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db))
}

fn addr(ip: &str) -> ConnectInfo<SocketAddr> {
    ConnectInfo(ip.parse::<SocketAddr>().unwrap())
}

fn req(ip: &str, method: &str, path: &str) -> Request<axum::body::Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .extension(addr(ip))
        .body(axum::body::Body::empty())
        .unwrap()
}

fn post_json(
    ip: &str,
    path: &str,
    body: serde_json::Value,
    cookie: Option<&str>,
    csrf: Option<&str>,
) -> Request<axum::body::Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .extension(addr(ip));
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    if let Some(t) = csrf {
        b = b.header("x-csrf-token", t);
    }
    b.body(axum::body::Body::from(
        serde_json::to_string(&body).unwrap(),
    ))
    .unwrap()
}

fn bearer_get(ip: &str, path: &str, token: &str) -> Request<axum::body::Body> {
    Request::builder()
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .extension(addr(ip))
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn csrf_from(resp: &axum::response::Response) -> Option<String> {
    let set_cookie = resp.headers().get(header::SET_COOKIE)?.to_str().ok()?;
    set_cookie
        .split(';')
        .next()
        .and_then(|c| c.strip_prefix("csrf_token="))
        .map(str::to_string)
}

fn create_user(db: &Db, email: &str, role: &str) -> i64 {
    db::upsert_user(db, email, "Test", None, role, &[]).unwrap();
    db::get_user_by_email(db, email).unwrap().id
}

fn session_for(db: &Db, email: &str, role: &str) -> String {
    let uid = create_user(db, email, role);
    db::create_auth_session(db, uid, 3600).unwrap()
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// Harvest the CSRF cookie through an authenticated GET (the browser would
/// already hold it from page loads).
async fn csrf_for_session(router: &Router, ip: &str, session: &str) -> String {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/me/tokens")
                .header(header::COOKIE, format!("persea_session={session}"))
                .extension(addr(ip))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    csrf_from(&resp).expect("csrf cookie must be set on every response")
}

/// Pair as an anonymous client (no cookies at all) and return the code.
async fn pair_code(router: &Router, ip: &str, hostname: &str) -> String {
    let resp = router
        .clone()
        .oneshot(post_json(
            ip,
            "/api/desktop/pair",
            serde_json::json!({ "hostname": hostname }),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let code = body["code"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 8);
    let expires_at = body["expires_at"].as_str().unwrap();
    assert!(
        expires_at.parse::<chrono::DateTime<chrono::Utc>>().is_ok(),
        "expires_at must be RFC 3339"
    );
    code
}

/// Confirm with a logged-in session, sending the CSRF double-submit pair.
async fn confirm_code(
    router: &Router,
    ip: &str,
    code: &str,
    session: &str,
) -> axum::response::Response {
    let csrf = csrf_for_session(router, ip, session).await;
    router
        .clone()
        .oneshot(post_json(
            ip,
            "/api/desktop/confirm",
            serde_json::json!({ "code": code }),
            Some(&format!("persea_session={session}; csrf_token={csrf}")),
            Some(&csrf),
        ))
        .await
        .unwrap()
}

async fn poll(router: &Router, ip: &str, code: &str) -> axum::response::Response {
    router
        .clone()
        .oneshot(req(
            ip,
            "GET",
            &format!("/api/desktop/pair/status?code={code}"),
        ))
        .await
        .unwrap()
}

// ── Full round trip ─────────────────────────────────────────────────────

#[tokio::test]
async fn full_round_trip_mints_token_exactly_once() {
    let db = test_db();
    let router = test_router(db.clone());

    let code = pair_code(&router, "10.0.0.1:8080", "dev-box").await;

    let resp = poll(&router, "10.0.0.1:8080", &code).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "pending");

    let session = session_for(&db, "alice@example.com", "poweruser");
    let resp = confirm_code(&router, "10.0.0.1:8080", &code, &session).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["device_name"], "dev-box");

    let resp = poll(&router, "10.0.0.1:8080", &code).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "approved");
    let token = body["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("rgu_"));
    assert_eq!(body["name"], "Persea Desktop (dev-box)");
    assert_eq!(body["max_role"], "poweruser");

    // The plaintext is handed out exactly once: the next poll is 410.
    let resp = poll(&router, "10.0.0.1:8080", &code).await;
    assert_eq!(resp.status(), StatusCode::GONE);

    // The minted token is an ordinary user token: Bearer auth works.
    let resp = router
        .clone()
        .oneshot(bearer_get("10.0.0.1:8080", "/api/me/tokens", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tokens = body_json(resp).await;
    assert_eq!(tokens.as_array().unwrap().len(), 1);
    assert_eq!(tokens[0]["name"], "Persea Desktop (dev-box)");
    assert_eq!(tokens[0]["max_role"], "poweruser");
    let token_id = tokens[0]["id"].as_i64().unwrap();

    // Revocable via DELETE /api/me/tokens/{id}; the Bearer dies with it.
    let csrf = csrf_for_session(&router, "10.0.0.1:8080", &session).await;
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/me/tokens/{token_id}"))
                .header(
                    header::COOKIE,
                    format!("persea_session={session}; csrf_token={csrf}"),
                )
                .header("x-csrf-token", &csrf)
                .extension(addr("10.0.0.1:8080"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = router
        .clone()
        .oneshot(bearer_get("10.0.0.1:8080", "/api/me/tokens", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── Single-use / wrong user ─────────────────────────────────────────────

#[tokio::test]
async fn code_is_single_use_across_users() {
    let db = test_db();
    let router = test_router(db.clone());
    let code = pair_code(&router, "10.0.0.2:8080", "box-a").await;

    let alice = session_for(&db, "alice@example.com", "poweruser");
    let bob = session_for(&db, "bob@example.com", "poweruser");

    let resp = confirm_code(&router, "10.0.0.2:8080", &code, &alice).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // A different logged-in user entering the same code fails.
    let resp = confirm_code(&router, "10.0.0.2:8080", &code, &bob).await;
    assert_eq!(resp.status(), StatusCode::GONE);

    // The same user re-confirming also fails.
    let resp = confirm_code(&router, "10.0.0.2:8080", &code, &alice).await;
    assert_eq!(resp.status(), StatusCode::GONE);

    // The pairing still belongs to alice: polling hands HER a token.
    let resp = poll(&router, "10.0.0.2:8080", &code).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "approved");
    let token = body["token"].as_str().unwrap().to_string();
    let resp = router
        .clone()
        .oneshot(bearer_get("10.0.0.2:8080", "/api/me/tokens", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await[0]["name"], "Persea Desktop (box-a)");
}

#[tokio::test]
async fn confirm_without_session_is_401() {
    let db = test_db();
    let router = test_router(db.clone());
    let code = pair_code(&router, "10.0.0.3:8080", "").await;

    let resp = router
        .clone()
        .oneshot(post_json(
            "10.0.0.3:8080",
            "/api/desktop/confirm",
            serde_json::json!({ "code": code }),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn confirm_requires_poweruser_or_higher() {
    let db = test_db();
    let router = test_router(db.clone());
    let code = pair_code(&router, "10.0.0.4:8080", "box-v").await;

    let viewer = session_for(&db, "viewer@example.com", "viewer");
    let resp = confirm_code(&router, "10.0.0.4:8080", &code, &viewer).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let operator = session_for(&db, "operator@example.com", "operator");
    let resp = confirm_code(&router, "10.0.0.4:8080", &code, &operator).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let admin = session_for(&db, "admin@example.com", "admin");
    let resp = confirm_code(&router, "10.0.0.4:8080", &code, &admin).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Expiry / unknown / malformed codes ──────────────────────────────────

#[tokio::test]
async fn expired_code_returns_410_everywhere() {
    let db = test_db();
    let router = test_router(db.clone());
    let session = session_for(&db, "alice@example.com", "poweruser");

    persea::api::pairing::insert_pairing(
        &db,
        sha256_hex("ABCD2345"),
        "old-box".to_string(),
        "2020-01-01 00:00:00".to_string(),
    )
    .await
    .unwrap();

    let resp = confirm_code(&router, "10.0.0.5:8080", "ABCD2345", &session).await;
    assert_eq!(resp.status(), StatusCode::GONE);

    let resp = poll(&router, "10.0.0.5:8080", "ABCD2345").await;
    assert_eq!(resp.status(), StatusCode::GONE);
}

#[tokio::test]
async fn unknown_and_malformed_codes_fail() {
    let db = test_db();
    let router = test_router(db.clone());
    let session = session_for(&db, "alice@example.com", "poweruser");

    let resp = confirm_code(&router, "10.0.0.6:8080", "ABCD2345", &session).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = poll(&router, "10.0.0.6:8080", "ABCD2345").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = confirm_code(&router, "10.0.0.6:8080", "short!!", &session).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = poll(&router, "10.0.0.6:8080", "OOO00000").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn code_typed_with_separator_normalizes() {
    let db = test_db();
    let router = test_router(db.clone());
    let code = pair_code(&router, "10.0.0.7:8080", "sep-box").await;
    let dashed = format!("{}-{}", &code[..4], &code[4..]);
    let lower = dashed.to_lowercase();

    let session = session_for(&db, "alice@example.com", "poweruser");
    let resp = confirm_code(&router, "10.0.0.7:8080", &lower, &session).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = poll(&router, "10.0.0.7:8080", &code).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["status"], "approved");
}

// ── Re-pair refreshes the device token ──────────────────────────────────

#[tokio::test]
async fn repair_replaces_previous_token_for_same_hostname() {
    let db = test_db();
    let router = test_router(db.clone());
    let session = session_for(&db, "alice@example.com", "poweruser");

    let code1 = pair_code(&router, "10.0.0.8:8080", "repeat-box").await;
    let resp = confirm_code(&router, "10.0.0.8:8080", &code1, &session).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = poll(&router, "10.0.0.8:8080", &code1).await;
    let token1 = body_json(resp).await["token"].as_str().unwrap().to_string();

    // Second pairing round for the same hostname: the old token is
    // replaced, so the name stays unique.
    let code2 = pair_code(&router, "10.0.0.8:8080", "repeat-box").await;
    let resp = confirm_code(&router, "10.0.0.8:8080", &code2, &session).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = poll(&router, "10.0.0.8:8080", &code2).await;
    let body = body_json(resp).await;
    assert_eq!(body["status"], "approved");
    let token2 = body["token"].as_str().unwrap().to_string();
    assert_ne!(token1, token2);

    let resp = router
        .clone()
        .oneshot(bearer_get("10.0.0.8:8080", "/api/me/tokens", &token2))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tokens = body_json(resp).await;
    let names: Vec<&str> = tokens
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["Persea Desktop (repeat-box)"]);

    let resp = router
        .clone()
        .oneshot(bearer_get("10.0.0.8:8080", "/api/me/tokens", &token1))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── Rate limits ─────────────────────────────────────────────────────────

#[tokio::test]
async fn pairing_creation_rate_limited_per_ip() {
    let db = test_db();
    let router = test_router(db.clone());

    for _ in 0..5 {
        let resp = router
            .clone()
            .oneshot(post_json(
                "10.0.0.9:8080",
                "/api/desktop/pair",
                serde_json::json!({}),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = router
        .clone()
        .oneshot(post_json(
            "10.0.0.9:8080",
            "/api/desktop/pair",
            serde_json::json!({}),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    // A different IP is not affected.
    let resp = router
        .clone()
        .oneshot(post_json(
            "10.0.0.10:8080",
            "/api/desktop/pair",
            serde_json::json!({}),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn status_polling_rate_limited_per_code() {
    let db = test_db();
    let router = test_router(db.clone());
    let code = pair_code(&router, "10.0.0.11:8080", "poll-box").await;

    for _ in 0..10 {
        let resp = poll(&router, "10.0.0.11:8080", &code).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = poll(&router, "10.0.0.11:8080", &code).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ── CSRF on the confirm POST ────────────────────────────────────────────

#[tokio::test]
async fn confirm_without_csrf_header_is_403() {
    let db = test_db();
    let router = test_router(db.clone());
    let code = pair_code(&router, "10.0.0.12:8080", "csrf-box").await;
    let session = session_for(&db, "alice@example.com", "poweruser");

    let resp = router
        .clone()
        .oneshot(post_json(
            "10.0.0.12:8080",
            "/api/desktop/confirm",
            serde_json::json!({ "code": code }),
            Some(&format!("persea_session={session}")),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
