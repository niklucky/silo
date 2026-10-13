//! `silo-server`: the sync server. Stores sealed revisions, grants and
//! tombstones in SQLite and hands them to the devices of the accounts they
//! are granted to. It holds no keys and cannot read a secret.
//!
//! The wire protocol is documented in [`silo_core::sync`].

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use silo_core::sync::{
    AccountReply, ChangesReply, ConnectionInfo, ConnectionsReply, DevicesReply, LoginRequest,
    PreloginReply, PushReply, PushRequest, RegisterRequest, ServerInfo, ServerKey, SessionReply,
};

pub mod accounts;
pub mod auth;
pub mod connections;
pub mod db;
pub mod error;
pub mod sync;

pub use db::Db;

use auth::{Auth, LoginLimiter};
use error::{ApiError, ApiResult};

/// Large enough for a push of file secrets; a client splits bigger batches.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub limiter: Arc<LoginLimiter>,
    pub server_key: Arc<ServerKey>,
}

impl AppState {
    pub fn new(db: Db) -> anyhow::Result<Self> {
        Ok(Self {
            server_key: Arc::new(db.server_key()?),
            db,
            limiter: Arc::default(),
        })
    }
}

pub fn app(state: AppState) -> Router {
    let v1 = Router::new()
        .route("/server", get(server_info))
        .route("/prelogin/{username}", get(prelogin))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/account", get(account))
        .route("/devices", get(devices))
        .route("/devices/{id}", delete(revoke_device))
        .route("/connections", get(list_connections))
        .route("/connections/{username}", put(request_connection))
        .route("/connections/{username}", delete(remove_connection))
        .route("/changes", get(changes))
        .route("/push", post(push));
    Router::new()
        .route("/health", get(health))
        .nest("/v1", v1)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(log_request))
        .with_state(state)
}

/// One line per request: method, path, status, time. Never headers (tokens)
/// or bodies, and not the query string.
async fn log_request(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    println!(
        "{method} {path} {} {} ms",
        response.status().as_u16(),
        started.elapsed().as_millis()
    );
    response
}

/// Seconds since the Unix epoch, from the host clock.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "server": env!("CARGO_PKG_VERSION"),
        "core": silo_core::version(),
    }))
}

/// Turns axum's plain-text JSON rejections into an [`ApiError`].
fn body<T>(payload: Result<Json<T>, JsonRejection>) -> ApiResult<T> {
    payload
        .map(|Json(value)| value)
        .map_err(|rejection| ApiError::invalid(rejection.body_text()))
}

async fn server_info(State(state): State<AppState>) -> Json<ServerInfo> {
    Json(ServerInfo {
        public_key: state.server_key.public_key(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    })
}

async fn prelogin(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> ApiResult<Json<PreloginReply>> {
    state
        .db
        .run(move |conn| accounts::prelogin(conn, &username))
        .await
        .map(Json)
}

async fn register(
    State(state): State<AppState>,
    payload: Result<Json<RegisterRequest>, JsonRejection>,
) -> ApiResult<Json<SessionReply>> {
    let request = body(payload)?;
    let now = unix_now();
    state
        .db
        .run(move |conn| {
            accounts::register(conn, &mut rand::rng(), now, &state.server_key, request)
        })
        .await
        .map(Json)
}

async fn login(
    State(state): State<AppState>,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> ApiResult<Json<SessionReply>> {
    let request = body(payload)?;
    let now = unix_now();
    let limiter = Arc::clone(&state.limiter);
    state
        .db
        .run(move |conn| accounts::login(conn, &limiter, &mut rand::rng(), now, request))
        .await
        .map(Json)
}

async fn logout(State(state): State<AppState>, auth: Auth) -> ApiResult<StatusCode> {
    state
        .db
        .run(move |conn| accounts::revoke_device(conn, &auth, &auth.device_id.clone()))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn account(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<AccountReply>> {
    state
        .db
        .run(move |conn| accounts::account_reply(conn, auth.account.id))
        .await
        .map(Json)
}

async fn devices(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<DevicesReply>> {
    state
        .db
        .run(move |conn| accounts::devices(conn, &auth))
        .await
        .map(|devices| Json(DevicesReply { devices }))
}

async fn revoke_device(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    state
        .db
        .run(move |conn| accounts::revoke_device(conn, &auth, &id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_connections(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<ConnectionsReply>> {
    state
        .db
        .run(move |conn| connections::list(conn, &auth))
        .await
        .map(|connections| Json(ConnectionsReply { connections }))
}

async fn request_connection(
    State(state): State<AppState>,
    auth: Auth,
    Path(username): Path<String>,
) -> ApiResult<Json<ConnectionInfo>> {
    let now = unix_now();
    state
        .db
        .run(move |conn| connections::request(conn, &auth, &username, now))
        .await
        .map(Json)
}

async fn remove_connection(
    State(state): State<AppState>,
    auth: Auth,
    Path(username): Path<String>,
) -> ApiResult<StatusCode> {
    state
        .db
        .run(move |conn| connections::remove(conn, &auth, &username))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ChangesQuery {
    #[serde(default)]
    since: u64,
    limit: Option<usize>,
}

async fn changes(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<ChangesQuery>,
) -> ApiResult<Json<ChangesReply>> {
    state
        .db
        .run(move |conn| sync::changes(conn, &auth, query.since, query.limit))
        .await
        .map(Json)
}

async fn push(
    State(state): State<AppState>,
    auth: Auth,
    payload: Result<Json<PushRequest>, JsonRejection>,
) -> ApiResult<Json<PushReply>> {
    let request = body(payload)?;
    let now = unix_now();
    state
        .db
        .run(move |conn| sync::push(conn, &auth, now, request))
        .await
        .map(Json)
}

#[cfg(test)]
mod tests;
