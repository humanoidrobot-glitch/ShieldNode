use std::sync::Arc;

use axum::{
    extract::State,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use tokio::sync::Mutex;

use super::bandwidth::BandwidthTracker;

// ── shared state ───────────────────────────────────────────────────────

/// Application state shared across axum handlers via [`State`].
#[derive(Clone)]
pub struct AppState {
    pub bandwidth: Arc<Mutex<BandwidthTracker>>,
}

// ── response types ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct MetricsResponse {
    total_bytes_in: u64,
    total_bytes_out: u64,
    active_sessions: usize,
}

#[derive(Serialize)]
struct SessionsResponse {
    sessions: Vec<SessionEntry>,
}

#[derive(Serialize)]
struct SessionEntry {
    session_id: u64,
    bytes_in: u64,
    bytes_out: u64,
}

// ── handlers ───────────────────────────────────────────────────────────

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn metrics(State(state): State<AppState>) -> Json<MetricsResponse> {
    let bw = state.bandwidth.lock().await;
    let (total_in, total_out) = bw.get_total_bytes();
    Json(MetricsResponse {
        total_bytes_in: total_in,
        total_bytes_out: total_out,
        active_sessions: bw.session_count(),
    })
}

async fn sessions(State(state): State<AppState>) -> Json<SessionsResponse> {
    let bw = state.bandwidth.lock().await;
    let sessions = bw
        .sessions()
        .iter()
        .map(|(&id, c)| SessionEntry {
            session_id: id,
            bytes_in: c.bytes_in,
            bytes_out: c.bytes_out,
        })
        .collect();
    Json(SessionsResponse { sessions })
}

// ── router constructor ─────────────────────────────────────────────────

/// Build the axum [`Router`] with shared bandwidth state.
pub fn router(bandwidth: Arc<Mutex<BandwidthTracker>>) -> Router {
    let state = AppState { bandwidth };
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/sessions", get(sessions))
        .with_state(state)
}
