use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use silo_server::{AppState, Db, accounts, app, unix_now};

/// Silo sync server. Stores encrypted secrets for the devices of its
/// accounts; holds no keys.
#[derive(Parser)]
#[command(name = "silo-server", version)]
struct Cli {
    /// SQLite database file, created if missing.
    #[arg(
        long,
        env = "SILO_SERVER_DB",
        default_value = "silo-server.db",
        global = true
    )]
    db: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the API (the default).
    Serve {
        /// Address to listen on. Put a TLS proxy in front of anything public.
        #[arg(long, env = "SILO_SERVER_ADDR", default_value = "127.0.0.1:8787")]
        addr: String,
    },
    /// Print a one-time code that lets one person create an account.
    Invite {
        /// Days until the code expires.
        #[arg(long, default_value_t = 7)]
        days: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let db = Db::open(&cli.db).with_context(|| format!("opening {}", cli.db.display()))?;
    match cli.command {
        Some(Command::Invite { days }) => {
            let code = db
                .with(|conn| accounts::create_invite(conn, &mut rand::rng(), unix_now(), days))
                .map_err(|err| anyhow::anyhow!(err.message))?;
            println!("{code}");
            eprintln!("Valid for {days} days, for one account.");
            Ok(())
        }
        Some(Command::Serve { addr }) => serve(db, &cli.db, &addr).await,
        None => {
            let addr =
                std::env::var("SILO_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());
            serve(db, &cli.db, &addr).await
        }
    }
}

async fn serve(db: Db, path: &std::path::Path, addr: &str) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    println!(
        "silo-server listening on http://{addr}, data in {}",
        path.display()
    );
    axum::serve(listener, app(AppState::new(db)?))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Ctrl+C, or SIGTERM from systemd or Docker.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
