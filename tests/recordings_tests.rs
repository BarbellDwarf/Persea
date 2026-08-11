//! Integration tests for the recordings API — listing, serving and deletion
//! of both plain `.guac` recordings and encrypted-at-rest `.guac.enc`
//! recordings (R94: encrypted recordings were invisible to the UI).
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete, get};
use axum::{Extension, Router};
use persea::api::reports::{delete_recording, list_recordings, serve_recording};
use persea::auth::AuthIdentity;
use persea::config::{Config, StorageConfig};
use persea::recording::{encrypt_recording_file, write_meta, RecordingMeta};
use persea::session::SessionManager;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tower::ServiceExt;

/// 64-char hex AES-256 key used for encrypted-at-rest test recordings.
const TEST_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

const PLAIN_CONTENT: &[u8] = b"4.3\nsize 800,600\n";
const ENC_PLAINTEXT: &[u8] = b"4.3\nsize 1024,768\n";

fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("persea-rec-test-{tag}-{}", uuid::Uuid::new_v4()))
}

fn admin() -> AuthIdentity {
    AuthIdentity::User {
        email: "admin@example.com".into(),
        name: "Admin".into(),
        role: "admin".into(),
        groups: vec![],
    }
}

fn test_router(recordings_dir: &Path, with_key: bool, identity: Option<AuthIdentity>) -> Router {
    let mut config = Config::default();
    config.recording_path = Some(recordings_dir.to_path_buf());
    if with_key {
        config.storage = Some(StorageConfig {
            encryption_key: Some(TEST_KEY_HEX.to_string()),
            ..Default::default()
        });
    }
    let manager = Arc::new(SessionManager::new(config, None));
    let router = Router::new()
        .route("/api/recordings", get(list_recordings))
        .route("/api/recordings/{name}", get(serve_recording))
        .route("/api/recordings/{name}", delete(delete_recording));
    match identity {
        Some(id) => router.layer(Extension(id)).with_state(manager),
        None => router.with_state(manager),
    }
}

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn del(path: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&body_bytes(resp).await).unwrap()
}

fn test_meta() -> RecordingMeta {
    RecordingMeta {
        address_book_entry: Some("shared/folder/server1".into()),
        created_at: "2025-01-15T10:30:00Z".into(),
        user: Some("admin@example.com".into()),
        folder: Some("shared/folder".into()),
        entry_display_name: Some("Production Server".into()),
        session_type: Some("rdp".into()),
    }
}

// ── Listing ──

#[tokio::test]
async fn listing_includes_plain_and_encrypted_recordings() {
    let dir = temp_dir("listing");
    std::fs::write(dir.join("session-a.guac"), PLAIN_CONTENT).unwrap();
    // Encrypted-at-rest recording: plaintext is written, encrypted in place.
    let enc_src = dir.join("session-b.guac");
    std::fs::write(&enc_src, ENC_PLAINTEXT).unwrap();
    write_meta(&enc_src, &test_meta()).unwrap();
    encrypt_recording_file(&enc_src, TEST_KEY_HEX).unwrap();
    assert!(dir.join("session-b.guac.enc").exists());
    assert!(!dir.join("session-b.guac").exists());
    // Decoys that must NOT be listed.
    std::fs::write(dir.join("notes.txt"), b"not a recording").unwrap();

    let router = test_router(&dir, true, Some(admin()));
    let resp = router.oneshot(get("/api/recordings")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let items = json.as_array().unwrap();

    let names: Vec<&str> = items.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert!(
        names.contains(&"session-a.guac"),
        "plain recording listed: {names:?}"
    );
    assert!(
        names.contains(&"session-b.guac.enc"),
        "encrypted recording listed: {names:?}"
    );
    assert!(!names.contains(&"notes.txt"), "decoy listed: {names:?}");

    let enc = items
        .iter()
        .find(|r| r["name"] == "session-b.guac.enc")
        .unwrap();
    assert!(enc["size_bytes"].as_u64().unwrap() > 0);
    assert!(!enc["modified"].as_str().unwrap().is_empty());
    // Sidecar metadata is attached for encrypted recordings too.
    assert_eq!(enc["user"], "admin@example.com");
    assert_eq!(enc["session_type"], "rdp");
    assert_eq!(enc["entry_display_name"], "Production Server");
    assert!(enc["duration_secs"].as_i64().unwrap() >= 0);

    let plain = items
        .iter()
        .find(|r| r["name"] == "session-a.guac")
        .unwrap();
    assert!(plain["size_bytes"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn listing_requires_poweruser_role() {
    let dir = temp_dir("listing-forbidden");
    std::fs::write(dir.join("session-a.guac"), PLAIN_CONTENT).unwrap();
    let viewer = AuthIdentity::User {
        email: "viewer@example.com".into(),
        name: "Viewer".into(),
        role: "viewer".into(),
        groups: vec![],
    };
    let router = test_router(&dir, false, Some(viewer));
    let resp = router.oneshot(get("/api/recordings")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn listing_without_identity_is_forbidden() {
    let dir = temp_dir("listing-noauth");
    std::fs::write(dir.join("session-a.guac"), PLAIN_CONTENT).unwrap();
    let router = test_router(&dir, false, None);
    let resp = router.oneshot(get("/api/recordings")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Serving ──

#[tokio::test]
async fn serve_plain_recording_streams_content() {
    let dir = temp_dir("serve-plain");
    std::fs::write(dir.join("plain.guac"), PLAIN_CONTENT).unwrap();
    let router = test_router(&dir, false, Some(admin()));
    let resp = router
        .oneshot(get("/api/recordings/plain.guac"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, PLAIN_CONTENT);
}

#[tokio::test]
async fn serve_encrypted_recording_by_enc_name_decrypts() {
    let dir = temp_dir("serve-enc-name");
    let src = dir.join("enc.guac");
    std::fs::write(&src, ENC_PLAINTEXT).unwrap();
    encrypt_recording_file(&src, TEST_KEY_HEX).unwrap();
    let router = test_router(&dir, true, Some(admin()));
    let resp = router
        .oneshot(get("/api/recordings/enc.guac.enc"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, ENC_PLAINTEXT);
}

#[tokio::test]
async fn serve_encrypted_recording_by_plain_name_decrypts() {
    let dir = temp_dir("serve-enc-plain-name");
    let src = dir.join("enc2.guac");
    std::fs::write(&src, ENC_PLAINTEXT).unwrap();
    encrypt_recording_file(&src, TEST_KEY_HEX).unwrap();
    let router = test_router(&dir, true, Some(admin()));
    // The plain `.guac` name transparently falls back to the enc sibling.
    let resp = router
        .oneshot(get("/api/recordings/enc2.guac"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, ENC_PLAINTEXT);
}

#[tokio::test]
async fn serve_unknown_recording_returns_error() {
    let dir = temp_dir("serve-missing");
    let router = test_router(&dir, false, Some(admin()));
    let resp = router
        .oneshot(get("/api/recordings/missing.guac"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ── Deletion ──

#[tokio::test]
async fn delete_encrypted_recording_removes_file_and_meta() {
    let dir = temp_dir("delete-enc");
    let src = dir.join("del.guac");
    std::fs::write(&src, ENC_PLAINTEXT).unwrap();
    write_meta(&src, &test_meta()).unwrap();
    encrypt_recording_file(&src, TEST_KEY_HEX).unwrap();
    assert!(dir.join("del.guac.enc").exists());
    assert!(dir.join("del.meta").exists());

    let router = test_router(&dir, true, Some(admin()));
    let resp = router
        .oneshot(del("/api/recordings/del.guac.enc"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(!dir.join("del.guac.enc").exists());
    assert!(!dir.join("del.meta").exists());
}

#[tokio::test]
async fn delete_plain_recording_removes_file() {
    let dir = temp_dir("delete-plain");
    std::fs::write(dir.join("plain2.guac"), PLAIN_CONTENT).unwrap();
    let router = test_router(&dir, false, Some(admin()));
    let resp = router
        .oneshot(del("/api/recordings/plain2.guac"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(!dir.join("plain2.guac").exists());
}

#[tokio::test]
async fn delete_plain_name_also_removes_enc_sibling() {
    let dir = temp_dir("delete-sibling");
    let src = dir.join("both.guac");
    std::fs::write(&src, ENC_PLAINTEXT).unwrap();
    encrypt_recording_file(&src, TEST_KEY_HEX).unwrap();
    assert!(dir.join("both.guac.enc").exists());

    let router = test_router(&dir, true, Some(admin()));
    let resp = router
        .oneshot(del("/api/recordings/both.guac"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(!dir.join("both.guac.enc").exists());
}

#[tokio::test]
async fn delete_unknown_recording_returns_error() {
    let dir = temp_dir("delete-missing");
    let router = test_router(&dir, false, Some(admin()));
    let resp = router
        .oneshot(del("/api/recordings/missing.guac"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn delete_requires_admin_role() {
    let dir = temp_dir("delete-forbidden");
    std::fs::write(dir.join("plain3.guac"), PLAIN_CONTENT).unwrap();
    let poweruser = AuthIdentity::User {
        email: "op@example.com".into(),
        name: "Operator".into(),
        role: "poweruser".into(),
        groups: vec![],
    };
    let router = test_router(&dir, false, Some(poweruser));
    let resp = router
        .oneshot(del("/api/recordings/plain3.guac"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(dir.join("plain3.guac").exists());
}
