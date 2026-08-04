//! Lightweight Prometheus-compatible metrics using atomic counters.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use tower::{Layer, Service};

struct Metrics {
    sessions_active: AtomicU64,
    sessions_total: AtomicU64,
    requests_total: AtomicU64,
    request_errors: AtomicU64,
    start_time: std::time::Instant,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

fn metrics() -> &'static Metrics {
    METRICS.get_or_init(|| Metrics {
        sessions_active: AtomicU64::new(0),
        sessions_total: AtomicU64::new(0),
        requests_total: AtomicU64::new(0),
        request_errors: AtomicU64::new(0),
        start_time: std::time::Instant::now(),
    })
}

pub fn session_active_inc() {
    metrics().sessions_active.fetch_add(1, Ordering::Relaxed);
}

pub fn session_active_dec() {
    metrics().sessions_active.fetch_sub(1, Ordering::Relaxed);
}

pub fn session_total_inc() {
    metrics().sessions_total.fetch_add(1, Ordering::Relaxed);
}

pub fn request_inc() {
    metrics().requests_total.fetch_add(1, Ordering::Relaxed);
}

pub fn error_inc() {
    metrics().request_errors.fetch_add(1, Ordering::Relaxed);
}

pub fn uptime_seconds() -> u64 {
    metrics().start_time.elapsed().as_secs()
}

pub fn render_prometheus() -> String {
    let m = metrics();
    let uptime_secs = m.start_time.elapsed().as_secs();
    format!(
        "# HELP persea_sessions_active Current active sessions\n\
         # TYPE persea_sessions_active gauge\n\
         persea_sessions_active {}\n\
         # HELP persea_sessions_total Total sessions created\n\
         # TYPE persea_sessions_total counter\n\
         persea_sessions_total {}\n\
         # HELP persea_requests_total Total HTTP requests\n\
         # TYPE persea_requests_total counter\n\
         persea_requests_total {}\n\
         # HELP persea_errors_total Total request errors (5xx responses)\n\
         # TYPE persea_errors_total counter\n\
         persea_errors_total {}\n\
         # HELP persea_uptime_seconds Server uptime in seconds\n\
         # TYPE persea_uptime_seconds gauge\n\
         persea_uptime_seconds {}\n",
        m.sessions_active.load(Ordering::Relaxed),
        m.sessions_total.load(Ordering::Relaxed),
        m.requests_total.load(Ordering::Relaxed),
        m.request_errors.load(Ordering::Relaxed),
        uptime_secs,
    )
}

// ── Tower layer for request counting ──

#[derive(Clone)]
pub struct MetricsLayer;

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsService { inner }
    }
}

#[derive(Clone)]
pub struct MetricsService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for MetricsService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        request_inc();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let result: Result<Response, S::Error> = inner.call(req).await;
            if let Ok(ref resp) = result {
                if resp.status().is_server_error() {
                    error_inc();
                }
            }
            result
        })
    }
}
