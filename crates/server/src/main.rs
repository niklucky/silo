use axum::{Json, Router, routing::get};
use serde_json::{Value, json};

const DEFAULT_ADDR: &str = "127.0.0.1:8787";

#[tokio::main]
async fn main() {
    let addr = std::env::var("SILO_SERVER_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_owned());

    let app = Router::new().route("/health", get(health));

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|err| panic!("failed to bind {addr}: {err}"));

    println!("silo-server listening on http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "server": env!("CARGO_PKG_VERSION"),
        "core": silo_core::version(),
    }))
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
}
