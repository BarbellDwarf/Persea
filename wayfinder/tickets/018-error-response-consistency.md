# Ticket: Error Response Consistency

**Type:** task
**Labels:** api, wayfinder:task

## Question

How to standardize API error responses across all 55+ endpoints?

### Current state:
- All errors use `{"error": "message"}` format — consistent
- But the conversion from domain errors to HTTP status is done inline in each handler via 30+ match blocks
- Pattern repeated 30+ times:
  ```rust
  match tokio::task::spawn_blocking(move || db::some_fn(&db_clone, ...)).await {
      Ok(Ok(val)) => ...,
      Ok(Err(e)) => (StatusCode::..., Json(json!({"error": ...}))).into_response(),
      _ => (StatusCode::..., Json(json!({"error": "failed to ..."}))).into_response(),
  }
  ```

### What needs standardizing:
1. **Error-to-HTTP mapping** — which domain error maps to which status code
2. **Error response body** — `{"error": "message"}` vs `{"error": "message", "code": "ENUM"}` vs `{"error": "message", "details": {...}}`
3. **JoinError handling** — `tokio::task::spawn_blocking` failures currently swallow errors silently in some places
4. **Error logging** — some errors are logged, some silently discarded

### Decision needed:

1. Centralized `impl IntoResponse for AppError` or per-handler mapping?
2. Error response format: simple `{"error": "message"}` or structured with error codes?
3. Should all errors be logged at `error!` level, or only unexpected ones?
4. Should `JoinError` (panic in spawn_blocking) return 500 with generic message?
