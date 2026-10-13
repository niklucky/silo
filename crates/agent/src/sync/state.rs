use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use silo_core::sync::{SessionReply, Tombstone};
use silo_core::vault::SecretId;

/// What `sync.json` holds: where to sync, as whom, and how far it got.
///
/// A secret is in step with the server when its local revision equals
/// `known[id]`; anything else is a local change still to push.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    pub server: String,
    pub username: String,
    pub device_id: String,
    pub token: String,
    /// The server's change counter up to which everything has been pulled.
    #[serde(default)]
    pub cursor: u64,
    #[serde(default)]
    pub account_version: u32,
    /// The server's current revision of each secret, as last seen.
    #[serde(default)]
    pub known: BTreeMap<SecretId, u32>,
    /// Local deletions not yet accepted by the server.
    #[serde(default)]
    pub deletes: BTreeMap<SecretId, Tombstone>,
    /// Secrets deleted on the server that were edited here afterwards. The
    /// edit wins: it is pushed as a restore on top of the deleted revision.
    #[serde(default)]
    pub deleted_remotely: BTreeMap<SecretId, u32>,
    /// Revisions the server refused; not sent again until they change.
    #[serde(default)]
    pub rejected: BTreeMap<SecretId, Rejection>,
    #[serde(default)]
    pub last_sync: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rejection {
    pub revision: u32,
    pub message: String,
}

impl SyncState {
    pub fn new(server: &str, session: &SessionReply) -> Self {
        Self {
            server: server.to_owned(),
            username: session.account.username.clone(),
            device_id: session.device_id.clone(),
            token: session.token.clone(),
            account_version: session.account.account_version,
            ..Self::default()
        }
    }
}

impl std::fmt::Debug for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncState")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("device_id", &self.device_id)
            .field("cursor", &self.cursor)
            .field("known", &self.known.len())
            .finish_non_exhaustive()
    }
}
