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
    /// Revisions sent in a push whose result has not come back yet, by the
    /// hex digest of the sealed revision: the number alone could also be
    /// another device's. If one reached the server after all and its secret
    /// was deleted here in the meantime, the next pull turns it into a
    /// deletion instead of bringing it back. Cleared once a pull has seen
    /// everything up to now.
    #[serde(default)]
    pub in_flight: BTreeMap<SecretId, String>,
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

/// What `silo sync logout` keeps of the sync state: how far it pulled, which
/// revisions the server is known to have, the deletions still to send, and
/// the uploads it never heard back about. Logging in to the
/// same account on the same server again picks it up, so edits made in
/// between are told apart from the server's.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    pub server: String,
    pub username: String,
    #[serde(default)]
    pub cursor: u64,
    #[serde(default)]
    pub known: BTreeMap<SecretId, u32>,
    #[serde(default)]
    pub deletes: BTreeMap<SecretId, Tombstone>,
    #[serde(default)]
    pub deleted_remotely: BTreeMap<SecretId, u32>,
    #[serde(default)]
    pub in_flight: BTreeMap<SecretId, String>,
}

impl SyncState {
    pub fn baseline(&self) -> Baseline {
        Baseline {
            server: self.server.clone(),
            username: self.username.clone(),
            cursor: self.cursor,
            known: self.known.clone(),
            deletes: self.deletes.clone(),
            deleted_remotely: self.deleted_remotely.clone(),
            in_flight: self.in_flight.clone(),
        }
    }

    /// Takes over a baseline from an earlier login to the same account on
    /// the same server. Returns false and changes nothing for any other.
    pub fn resume(&mut self, baseline: Baseline) -> bool {
        if baseline.server != self.server || baseline.username != self.username {
            return false;
        }
        self.cursor = baseline.cursor;
        self.known = baseline.known;
        self.deletes = baseline.deletes;
        self.deleted_remotely = baseline.deleted_remotely;
        self.in_flight = baseline.in_flight;
        true
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
