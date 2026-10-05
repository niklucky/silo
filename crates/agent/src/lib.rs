//! `secret-agent`: the local vault service.
//!
//! One agent process per user holds the unlocked account keys and the data key of
//! every readable secret. Clients (the CLI today, desktop app and extension later)
//! talk to it over a Unix domain socket, one JSON object per line. See
//! [`protocol`] for the wire types and [`store`] for the on-disk layout.
//!
//! ```text
//! $SECRET_HOME            default ~/.secret, mode 0700
//! ├── account.json        AccountRecord: KDF params, public key, wrapped secret key
//! ├── vault/<id>.json     StoredSecret: latest SealedSecret plus its grants
//! ├── agent.sock          Unix socket, mode 0600  (override: SECRET_AGENT_SOCKET)
//! └── agent.log           stdout/stderr of a detached agent
//! ```
//!
//! The agent is the only process that ever sees a password or a data key. Clients
//! receive decrypted secrets over the socket; the socket is protected by file
//! permissions, so the trust boundary is "same user on this machine".

pub mod client;
pub mod paths;
pub mod protocol;
pub mod server;
pub mod session;
pub mod store;

pub use client::{Client, ClientError};
pub use paths::Paths;
pub use protocol::{AgentError, Reply, Request, Response};
pub use session::Session;
pub use store::{Store, StoreError, StoredSecret};

/// Version of this crate, reported in [`protocol::StatusInfo`].
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Seconds since the Unix epoch, from the host clock.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
