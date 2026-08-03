//! Integration tests for API handlers.
use axum::http::{header, Request, StatusCode};
use axum::routing::{delete, get, post, put};
use axum::{middleware, Extension, Router};
use rustguac::auth::TrustedProxies;
use rustguac::db::{self, Db};
use tower::ServiceExt;

fn test_db() -> Db { db::init_db(std::path::Path::new(":memory:")).unwrap() }
fn test_router(db: Db) -> Router {
    Router::new()
        .route("/api/users", get(rustguac::api::users::list_users))
        .route("/api/users/{email}/role", put(rustguac::api::users::set_user_role))
        .route("/api/users/{email}", delete(rustguac::api::users::delete_user))
        .route("/api/users/{email}/disable", post(rustguac::api::users::disable_user))
        .route("/api/users/{email}/enable", post(rustguac::api::users::enable_user))
        .route("/api/me/tokens", get(rustguac::api::tokens::list_my_tokens))
        .route("/api/me/tokens", post(rustguac::api::tokens::create_my_token))
        .route("/api/me/tokens/{id}", delete(rustguac::api::tokens::revoke_my_token))
        .route("/api/admin/user-tokens", get(rustguac::api::tokens::admin_list_user_tokens))
        .route("/api/admin/user-tokens", post(rustguac::api::tokens::admin_create_user_token))
        .route("/api/admin/user-tokens/{id}", delete(rustguac::api::tokens::admin_revoke_user_token))
        .layer(middleware::from_fn(rustguac::auth::require_auth))
        .layer(Extension(TrustedProxies::default()))
        .layer(Extension(db))
}
fn create_admin(db: &Db, n: &str) -> String { db::add_admin(db, n, None, None).unwrap() }
fn create_user(db: &Db, e: &str, n: &str, r: &str) { db::upsert_user(db, e, n, None, r, &[]).unwrap() }
fn g(key: &str, p: &str) -> Request<axum::body::Body> { Request::builder().uri(p).header(header::AUTHORIZATION, format!("Bearer {}", key)).body(axum::body::Body::empty()).unwrap() }
fn g_no(p: &str) -> Request<axum::body::Body> { Request::builder().uri(p).body(axum::body::Body::empty()).unwrap() }
fn g_bad(p: &str) -> Request<axum::body::Body> { Request::builder().uri(p).header(header::AUTHORIZATION, "Bearer bad").body(axum::body::Body::empty()).unwrap() }
fn p(key: &str, p: &str, b: serde_json::Value) -> Request<axum::body::Body> { Request::builder().method("POST").uri(p).header(header::AUTHORIZATION, format!("Bearer {}", key)).header(header::CONTENT_TYPE, "application/json").body(axum::body::Body::from(serde_json::to_string(&b).unwrap())).unwrap() }
fn pu(key: &str, p: &str, b: serde_json::Value) -> Request<axum::body::Body> { Request::builder().method("PUT").uri(p).header(header::AUTHORIZATION, format!("Bearer {}", key)).header(header::CONTENT_TYPE, "application/json").body(axum::body::Body::from(serde_json::to_string(&b).unwrap())).unwrap() }
fn del(key: &str, p: &str) -> Request<axum::body::Body> { Request::builder().method("DELETE").uri(p).header(header::AUTHORIZATION, format!("Bearer {}", key)).body(axum::body::Body::empty()).unwrap() }
fn s_setup(db: &Db, e: &str, r: &str) -> String { create_user(db, e, "T", r); db::create_auth_session(db, db::get_user_by_email(db, e).unwrap().id, 3600).unwrap() }
fn sg(m: &str, p: &str, t: &str) -> Request<axum::body::Body> { Request::builder().method(m).uri(p).header(header::COOKIE, format!("rustguac_session={}", t)).body(axum::body::Body::empty()).unwrap() }
fn sp(p: &str, t: &str, b: serde_json::Value) -> Request<axum::body::Body> { Request::builder().method("POST").uri(p).header(header::COOKIE, format!("rustguac_session={}", t)).header(header::CONTENT_TYPE, "application/json").body(axum::body::Body::from(serde_json::to_string(&b).unwrap())).unwrap() }
async fn j(r: axum::response::Response) -> serde_json::Value { serde_json::from_slice(&axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap()).unwrap() }

#[tokio::test] async fn no_auth_401() { assert_eq!(test_router(test_db()).oneshot(g_no("/api/users")).await.unwrap().status(), StatusCode::UNAUTHORIZED); }
#[tokio::test] async fn bad_key_401() { assert_eq!(test_router(test_db()).oneshot(g_bad("/api/users")).await.unwrap().status(), StatusCode::UNAUTHORIZED); }
#[tokio::test] async fn ok_key_200() { let db=test_db(); let k=create_admin(&db,"a"); assert_eq!(test_router(db).oneshot(g(&k,"/api/users")).await.unwrap().status(), StatusCode::OK); }
#[tokio::test] async fn list_empty() { let db=test_db(); let k=create_admin(&db,"a"); let v=j(test_router(db).oneshot(g(&k,"/api/users")).await.unwrap()); assert!(v.as_array().unwrap().is_empty()); }
#[tokio::test] async fn list_data() { let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"x@t","X","v"); create_user(&db,"y@t","Y","o"); let v=j(test_router(db).oneshot(g(&k,"/api/users")).await.unwrap()); assert_eq!(v.as_array().unwrap().len(), 2); }
#[tokio::test] async fn set_role() { let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"u@t","U","v"); test_router(db.clone()).oneshot(pu(&k,"/api/users/u@t/role",serde_json::json!({"role":"operator"}))).await.unwrap(); assert_eq!(db::get_user_by_email(&db,"u@t").unwrap().role,"operator"); }
#[tokio::test] async fn set_role_bad() { let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"u@t","U","v"); assert_eq!(test_router(db).oneshot(pu(&k,"/api/users/u@t/role",serde_json::json!({"role":"bad"}))).await.unwrap().status(), StatusCode::INTERNAL_SERVER_ERROR); }
#[tokio::test] async fn set_role_404() { let db=test_db(); let k=create_admin(&db,"a"); assert_eq!(test_router(db).oneshot(pu(&k,"/api/users/x@t/role",serde_json::json!({"role":"v"}))).await.unwrap().status(), StatusCode::NOT_FOUND); }
#[tokio::test] async fn del_user() { let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"u@t","U","v"); assert_eq!(test_router(db.clone()).oneshot(del(&k,"/api/users/u@t")).await.unwrap().status(), StatusCode::NO_CONTENT); assert!(db::get_user_by_email(&db,"u@t").is_err()); }
#[tokio::test] async fn del_404() { let db=test_db(); let k=create_admin(&db,"a"); assert_eq!(test_router(db).oneshot(del(&k,"/api/users/x@t")).await.unwrap().status(), StatusCode::NOT_FOUND); }
#[tokio::test] async fn dis_en() { let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"u@t","U","v"); test_router(db.clone()).oneshot(p(&k,"/api/users/u@t/disable",serde_json::json!({}))).await.unwrap(); assert!(db::get_user_by_email(&db,"u@t").unwrap().disabled); test_router(db.clone()).oneshot(p(&k,"/api/users/u@t/enable",serde_json::json!({}))).await.unwrap(); assert!(!db::get_user_by_email(&db,"u@t").unwrap().disabled); }
#[tokio::test] async fn viewer_no_list() { let db=test_db(); let s=s_setup(&db,"v@t","v"); assert_eq!(test_router(db).oneshot(sg("GET","/api/users",&s)).await.unwrap().status(), StatusCode::FORBIDDEN); }
#[tokio::test] async fn tok_empty() { let db=test_db(); let s=s_setup(&db,"u@t","p"); let v=j(test_router(db).oneshot(sg("GET","/api/me/tokens",&s)).await.unwrap()); assert!(v.as_array().unwrap().is_empty()); }
#[tokio::test] async fn tok_cr_list() { let db=test_db(); let s=s_setup(&db,"u@t","p"); let r=test_router(db.clone()).oneshot(sp("/api/me/tokens",&s,serde_json::json!({"name":"t1"}))).await.unwrap(); assert_eq!(r.status(),StatusCode::OK); let v=j(r); assert!(v["token"].as_str().unwrap().starts_with("rgu_")); let tid=v["id"].as_i64().unwrap(); let v2=j(test_router(db).oneshot(sg("GET","/api/me/tokens",&s)).await.unwrap()); assert_eq!(v2.as_array().unwrap().len(),1); assert_eq!(v2[0]["id"].as_i64().unwrap(),tid); }
#[tokio::test] async fn tok_empty_name() { let db=test_db(); let s=s_setup(&db,"u@t","p"); assert_eq!(test_router(db).oneshot(sp("/api/me/tokens",&s,serde_json::json!({"name":""}))).await.unwrap().status(),StatusCode::INTERNAL_SERVER_ERROR); }
#[tokio::test] async fn tok_dup() { let db=test_db(); let s=s_setup(&db,"u@t","p"); test_router(db.clone()).oneshot(sp("/api/me/tokens",&s,serde_json::json!({"name":"d"}))).await.unwrap(); assert_eq!(test_router(db).oneshot(sp("/api/me/tokens",&s,serde_json::json!({"name":"d"}))).await.unwrap().status(),StatusCode::CONFLICT); }
#[tokio::test] async fn tok_revoke() { let db=test_db(); let s=s_setup(&db,"u@t","p"); let r=test_router(db.clone()).oneshot(sp("/api/me/tokens",&s,serde_json::json!({"name":"r"}))).await.unwrap(); let tid=j(r)["id"].as_i64().unwrap(); assert_eq!(test_router(db.clone()).oneshot(sg("DELETE",&format!("/api/me/tokens/{}",tid),&s)).await.unwrap().status(),StatusCode::OK); assert!(db::list_user_tokens(&db,db::get_user_by_email(&db,"u@t").unwrap().id).unwrap().is_empty()); }
#[tokio::test] async fn tok_revoke_404() { let db=test_db(); let s=s_setup(&db,"u@t","p"); assert_eq!(test_router(db).oneshot(sg("DELETE","/api/me/tokens/99999",&s)).await.unwrap().status(),StatusCode::NOT_FOUND); }
#[tokio::test] async fn viewer_no_tok() { let db=test_db(); let s=s_setup(&db,"u@t","v"); assert_eq!(test_router(db).oneshot(sp("/api/me/tokens",&s,serde_json::json!({"name":"x"}))).await.unwrap().status(),StatusCode::FORBIDDEN); }
#[tokio::test] async fn adm_list_empty() { let db=test_db(); let k=create_admin(&db,"a"); let v=j(test_router(db).oneshot(g(&k,"/api/admin/user-tokens")).await.unwrap()); assert!(v.as_array().unwrap().is_empty()); }
#[tokio::test] async fn adm_cr() { let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"u@t","U","v"); let r=test_router(db).oneshot(p(&k,"/api/admin/user-tokens",serde_json::json!({"email":"u@t","name":"at"}))).await.unwrap(); assert_eq!(r.status(),StatusCode::OK); let v=j(r); assert_eq!(v["email"].as_str().unwrap(),"u@t"); assert!(v["token"].as_str().unwrap().starts_with("rgu_")); }
#[tokio::test] async fn adm_cr_404() { let db=test_db(); let k=create_admin(&db,"a"); assert_eq!(test_router(db).oneshot(p(&k,"/api/admin/user-tokens",serde_json::json!({"email":"x@t","name":"t"}))).await.unwrap().status(),StatusCode::NOT_FOUND); }
#[tokio::test] async fn adm_rev() { let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"u@t","U","v"); let r=test_router(db.clone()).oneshot(p(&k,"/api/admin/user-tokens",serde_json::json!({"email":"u@t","name":"r"}))).await.unwrap(); let tid=j(r)["id"].as_i64().unwrap(); assert_eq!(test_router(db.clone()).oneshot(del(&k,&format!("/api/admin/user-tokens/{}",tid))).await.unwrap().status(),StatusCode::OK); assert!(db::list_user_tokens(&db,db::get_user_by_email(&db,"u@t").unwrap().id).unwrap().is_empty()); }
#[tokio::test] async fn adm_rev_404() { let db=test_db(); let k=create_admin(&db,"a"); assert_eq!(test_router(db).oneshot(del(&k,"/api/admin/user-tokens/99999")).await.unwrap().status(),StatusCode::NOT_FOUND); }
#[tokio::test] async fn pu_no_adm_tok() { let db=test_db(); let s=s_setup(&db,"p@t","p"); assert_eq!(test_router(db).oneshot(sg("GET","/api/admin/user-tokens",&s)).await.unwrap().status(),StatusCode::FORBIDDEN); }
