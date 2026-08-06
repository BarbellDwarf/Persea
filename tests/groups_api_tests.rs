//! Integration tests for the admin local-groups API (wayfinder ticket #029):
//! GET/POST `/api/admin/groups`, GET/PUT/DELETE `/{id}`,
//! POST `/{id}/mappings`, DELETE `/{id}/mappings/{mapping_id}`.
//!
//! Schema setup mirrors `tests/settings_api_tests.rs`: in-memory SQLite via
//! `db::init_db` (which creates `local_groups` + `group_mappings`), then
//! `tower::ServiceExt::oneshot` against a router wired like `src/main.rs`.
//! The handlers live in `src/api/groups.rs`, included directly via `#[path]`
//! with crate-root shims so these tests compile independently of the
//! route-wiring orchestrator step.

mod audit {
    pub use persea::audit::*;
}
mod auth {
    pub use persea::auth::*;
}
mod db {
    pub use persea::db::*;
}
mod error {
    pub use persea::error::*;
}

#[path = "../src/api/groups.rs"]
mod groups;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::{delete, get, post, put};
use axum::{middleware, Extension, Router};
use persea::auth::TrustedProxies;
use persea::db::Db;
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower::ServiceExt;

fn test_db() -> Db {
    db::init_db(std::path::Path::new(":memory:")).unwrap()
}

/// Mirrors the real route wiring: `require_auth` middleware + extensions.
fn test_router(db: Db) -> Router {
    Router::new()
        .route(
            "/api/admin/groups",
            get(groups::list_groups).post(groups::create_group),
        )
        .route(
            "/api/admin/groups/{id}",
            get(groups::get_group)
                .put(groups::update_group)
                .delete(groups::delete_group),
        )
        .route(
            "/api/admin/groups/{id}/mappings",
            post(groups::add_group_mapping),
        )
        .route(
            "/api/admin/groups/{id}/mappings/{mapping_id}",
            delete(groups::remove_group_mapping),
        )
        .layer(middleware::from_fn(persea::auth::require_auth))
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db))
}

/// No auth middleware — lets requests reach the handlers with no identity so
/// the handlers' own admin role check can be exercised (403).
fn bare_router(db: Db) -> Router {
    Router::new()
        .route(
            "/api/admin/groups",
            get(groups::list_groups).post(groups::create_group),
        )
        .route(
            "/api/admin/groups/{id}",
            get(groups::get_group)
                .put(groups::update_group)
                .delete(groups::delete_group),
        )
        .route(
            "/api/admin/groups/{id}/mappings",
            post(groups::add_group_mapping),
        )
        .route(
            "/api/admin/groups/{id}/mappings/{mapping_id}",
            delete(groups::remove_group_mapping),
        )
        .layer(Extension(db))
}

fn create_admin(db: &Db, name: &str) -> String {
    db::add_admin(db, name, None, None).unwrap()
}

fn fake_addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap())
}

fn admin_req(method: &str, key: &str, path: &str, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {}", key))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(fake_addr());
    let body = match body {
        Some(b) => Body::from(serde_json::to_string(&b).unwrap()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

fn no_auth_req(method: &str, path: &str, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    let body = match body {
        Some(b) => Body::from(serde_json::to_string(&b).unwrap()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Create a group through the API and return its id.
async fn create_group_via_api(router: &Router, key: &str, name: &str, description: &str) -> i64 {
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            key,
            "/api/admin/groups",
            Some(json!({ "name": name, "description": description })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "create {name}");
    let json = body_json(resp).await;
    json["id"].as_i64().unwrap()
}

// ── CRUD round trip ──

#[tokio::test]
async fn create_list_rename_delete_roundtrip() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);

    let id = create_group_via_api(&router, &key, "engineers", "The engineering team").await;

    // Listed with counts.
    let resp = router
        .clone()
        .oneshot(admin_req("GET", &key, "/api/admin/groups", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["groups"].as_array().unwrap().len(), 1);
    let g = &json["groups"][0];
    assert_eq!(g["id"].as_i64(), Some(id));
    assert_eq!(g["name"], "engineers");
    assert_eq!(g["description"], "The engineering team");
    assert_eq!(g["provider_group_count"].as_i64(), Some(0));
    assert_eq!(g["folder_count"].as_i64(), Some(0));

    // Rename.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "PUT",
            &key,
            &format!("/api/admin/groups/{}", id),
            Some(json!({ "name": "eng" })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "eng");
    assert_eq!(json["description"], "The engineering team");

    // Delete.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "DELETE",
            &key,
            &format!("/api/admin/groups/{}", id),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["ok"], true);
    assert_eq!(json["mappings_removed"].as_i64(), Some(0));

    // Gone.
    let resp = router
        .clone()
        .oneshot(admin_req("GET", &key, "/api/admin/groups", None))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);
}

// ── Validation ──

#[tokio::test]
async fn create_group_rejects_empty_name() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_req(
            "POST",
            &key,
            "/api/admin/groups",
            Some(json!({ "name": "   " })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error_code"].as_str().unwrap(), "VALIDATION_ERROR");
}

#[tokio::test]
async fn create_group_rejects_duplicate_name() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    create_group_via_api(&router, &key, "dup", "").await;

    let resp = router
        .oneshot(admin_req(
            "POST",
            &key,
            "/api/admin/groups",
            Some(json!({ "name": "dup" })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json = body_json(resp).await;
    assert_eq!(json["error_code"].as_str().unwrap(), "CONFLICT");
}

#[tokio::test]
async fn rename_to_duplicate_name_rejected() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    create_group_via_api(&router, &key, "alpha", "").await;
    let beta = create_group_via_api(&router, &key, "beta", "").await;

    let resp = router
        .oneshot(admin_req(
            "PUT",
            &key,
            &format!("/api/admin/groups/{}", beta),
            Some(json!({ "name": "alpha" })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn update_description_only_keeps_name() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let id = create_group_via_api(&router, &key, "ops", "old").await;

    let resp = router
        .oneshot(admin_req(
            "PUT",
            &key,
            &format!("/api/admin/groups/{}", id),
            Some(json!({ "description": "new" })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "ops");
    assert_eq!(json["description"], "new");
}

// ── 404s ──

#[tokio::test]
async fn unknown_group_is_404() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);

    for (method, path, body) in [
        ("GET", "/api/admin/groups/999", None),
        ("PUT", "/api/admin/groups/999", Some(json!({ "name": "x" }))),
        ("DELETE", "/api/admin/groups/999", None),
        (
            "POST",
            "/api/admin/groups/999/mappings",
            Some(json!({ "provider_group": "pg" })),
        ),
    ] {
        let resp = router
            .clone()
            .oneshot(admin_req(method, &key, path, body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{} {}", method, path);
    }
}

// ── Mappings ──

#[tokio::test]
async fn mapping_create_lists_and_replaces_same_provider_group() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let a = create_group_via_api(&router, &key, "group-a", "").await;
    let b = create_group_via_api(&router, &key, "group-b", "").await;

    // Map "corp-admins" to group A.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &key,
            &format!("/api/admin/groups/{}/mappings", a),
            Some(json!({ "provider_group": "corp-admins" })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let mapping = body_json(resp).await;
    assert_eq!(mapping["group_id"].as_i64(), Some(a));
    let mapping_id = mapping["id"].as_i64().unwrap();

    // Same provider group mapped to group B replaces the old mapping.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &key,
            &format!("/api/admin/groups/{}/mappings", b),
            Some(json!({ "provider_group": "corp-admins" })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Group A no longer has it; group B does.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            &key,
            &format!("/api/admin/groups/{}", a),
            None,
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["mappings"].as_array().unwrap().len(), 0);

    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            &key,
            &format!("/api/admin/groups/{}", b),
            None,
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    let mappings = json["mappings"].as_array().unwrap();
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0]["provider_group"], "corp-admins");
    assert_ne!(mappings[0]["id"].as_i64(), Some(mapping_id));

    // provider_group_count reflects the new mapping.
    let resp = router
        .clone()
        .oneshot(admin_req("GET", &key, "/api/admin/groups", None))
        .await
        .unwrap();
    let json = body_json(resp).await;
    let groups = json["groups"].as_array().unwrap();
    for g in groups {
        let expected = if g["id"].as_i64() == Some(b) { 1 } else { 0 };
        assert_eq!(g["provider_group_count"].as_i64(), Some(expected));
    }
}

#[tokio::test]
async fn mapping_delete_and_unknown_mapping_404() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let a = create_group_via_api(&router, &key, "group-a", "").await;

    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &key,
            &format!("/api/admin/groups/{}/mappings", a),
            Some(json!({ "provider_group": "pg-1" })),
        ))
        .await
        .unwrap();
    let mapping_id = body_json(resp).await["id"].as_i64().unwrap();

    // Delete.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "DELETE",
            &key,
            &format!("/api/admin/groups/{}/mappings/{}", a, mapping_id),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Second delete → 404.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "DELETE",
            &key,
            &format!("/api/admin/groups/{}/mappings/{}", a, mapping_id),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Unknown mapping on a different group → 404 even if it exists elsewhere.
    let b = create_group_via_api(&router, &key, "group-b", "").await;
    let resp = router
        .oneshot(admin_req(
            "DELETE",
            &key,
            &format!("/api/admin/groups/{}/mappings/{}", b, mapping_id),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_group_removes_its_mappings() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let a = create_group_via_api(&router, &key, "group-a", "").await;
    let b = create_group_via_api(&router, &key, "group-b", "").await;

    for (gid, pg) in [(a, "pg-1"), (a, "pg-2"), (b, "pg-3")] {
        let resp = router
            .clone()
            .oneshot(admin_req(
                "POST",
                &key,
                &format!("/api/admin/groups/{}/mappings", gid),
                Some(json!({ "provider_group": pg })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let resp = router
        .clone()
        .oneshot(admin_req(
            "DELETE",
            &key,
            &format!("/api/admin/groups/{}", a),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["mappings_removed"].as_i64(), Some(2));

    // Group B's mapping survives.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            &key,
            &format!("/api/admin/groups/{}", b),
            None,
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["mappings"].as_array().unwrap().len(), 1);
}

// ── Detail: known-groups merge ──

#[tokio::test]
async fn get_group_merges_known_groups_with_mapping_status() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    // Seed known groups via the group-to-role mapping table + seen groups.
    db::create_group_mapping(&db, "corp-admins", "admin").unwrap();
    db::upsert_seen_groups(&db, &["corp-devs".to_string()]).unwrap();
    let router = test_router(db.clone());
    let a = create_group_via_api(&router, &key, "group-a", "").await;
    let b = create_group_via_api(&router, &key, "group-b", "").await;

    // corp-admins → group A, corp-devs → group B.
    for (gid, pg) in [(a, "corp-admins"), (b, "corp-devs")] {
        let resp = router
            .clone()
            .oneshot(admin_req(
                "POST",
                &key,
                &format!("/api/admin/groups/{}/mappings", gid),
                Some(json!({ "provider_group": pg })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let resp = router
        .oneshot(admin_req(
            "GET",
            &key,
            &format!("/api/admin/groups/{}", a),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["group"]["name"], "group-a");

    let known = json["known_groups"].as_array().unwrap();
    assert_eq!(known.len(), 2);
    let admins = known.iter().find(|k| k["name"] == "corp-admins").unwrap();
    assert_eq!(admins["mapped"], true);
    assert_eq!(admins["group_id"].as_i64(), Some(a));
    assert_eq!(admins["group_name"], "group-a");
    let devs = known.iter().find(|k| k["name"] == "corp-devs").unwrap();
    assert_eq!(devs["mapped"], true);
    assert_eq!(devs["group_id"].as_i64(), Some(b));
    assert_eq!(devs["group_name"], "group-b");
}

// ── folder_count ──

#[tokio::test]
async fn folder_count_counts_folders_referencing_the_group_name() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());

    // Folder 1: entries listing "admins" (and "ops").
    let f1 = db::create_ab_folder(&db, "shared", "Prod", "").unwrap();
    db::create_ab_entry(
        &db,
        f1,
        "host-a",
        "Host A",
        "ssh",
        "10.0.0.1",
        Some(22),
        "root",
        "{}",
        "admins,ops",
    )
    .unwrap();
    db::create_ab_entry(
        &db,
        f1,
        "host-b",
        "Host B",
        "ssh",
        "10.0.0.2",
        Some(22),
        "root",
        "{}",
        "ops",
    )
    .unwrap();
    // Folder 2: only "devs" (case-sensitive: "Admins" must not match).
    let f2 = db::create_ab_folder(&db, "shared", "Dev", "").unwrap();
    db::create_ab_entry(
        &db,
        f2,
        "host-c",
        "Host C",
        "ssh",
        "10.0.0.3",
        Some(22),
        "root",
        "{}",
        "Admins,devs",
    )
    .unwrap();

    create_group_via_api(&router, &key, "admins", "").await;

    let resp = router
        .oneshot(admin_req("GET", &key, "/api/admin/groups", None))
        .await
        .unwrap();
    let json = body_json(resp).await;
    let g = &json["groups"][0];
    assert_eq!(g["name"], "admins");
    assert_eq!(g["folder_count"].as_i64(), Some(1));
}

// ── Admin enforcement ──

#[tokio::test]
async fn all_endpoints_require_admin() {
    let db = test_db();
    let router = bare_router(db);

    let cases: Vec<(&str, &str, Option<Value>)> = vec![
        ("GET", "/api/admin/groups", None),
        ("POST", "/api/admin/groups", Some(json!({ "name": "x" }))),
        ("GET", "/api/admin/groups/1", None),
        ("PUT", "/api/admin/groups/1", Some(json!({ "name": "x" }))),
        ("DELETE", "/api/admin/groups/1", None),
        (
            "POST",
            "/api/admin/groups/1/mappings",
            Some(json!({ "provider_group": "pg" })),
        ),
        ("DELETE", "/api/admin/groups/1/mappings/1", None),
    ];
    for (method, path, body) in cases {
        let resp = router
            .clone()
            .oneshot(no_auth_req(method, path, body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{} {}", method, path);
        let json = body_json(resp).await;
        assert_eq!(json["error_code"].as_str().unwrap(), "FORBIDDEN");
    }
}
