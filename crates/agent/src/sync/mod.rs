//! Sync with a `silo-server`: setup (register, log in, log out), the HTTP
//! client, and the engine that pulls and pushes.
//!
//! The agent drives it: on unlock, a couple of seconds after each change,
//! every few minutes while unlocked, and on `silo sync`. Sync state lives in
//! `sync.json` next to the vault; see [`SyncState`].

mod engine;
mod http;
mod state;

pub use engine::{PUSH_BATCH, SyncReport, Vault, VaultAccess, record_deletion, run};
pub use http::{HttpClient, normalize_server};
pub use state::{Baseline, Rejection, SyncState};

use silo_core::AccountKeys;
use silo_core::account::AccountRecord;
use silo_core::crypto::AuthKey;
use silo_core::sync::{self, ErrorCode, LoginRequest, RegisterRequest};

use crate::protocol::AgentError;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sync is not set up; run `silo sync login` or `silo sync register`")]
    NotConfigured,
    #[error("already syncing with {0}; run `silo sync logout` first")]
    AlreadyConfigured(String),
    #[error("vault is locked; run `silo unlock`")]
    Locked,
    #[error("{0}")]
    Config(String),
    #[error("cannot reach the server: {0}")]
    Network(String),
    #[error("server: {message}")]
    Server {
        status: u16,
        code: Option<ErrorCode>,
        message: String,
    },
    #[error("unexpected reply from the server: {0}")]
    Protocol(String),
    #[error(transparent)]
    Agent(#[from] AgentError),
}

impl From<crate::store::StoreError> for SyncError {
    fn from(err: crate::store::StoreError) -> Self {
        Self::Agent(err.into())
    }
}

impl From<silo_core::Error> for SyncError {
    fn from(err: silo_core::Error) -> Self {
        Self::Agent(err.into())
    }
}

impl From<SyncError> for AgentError {
    fn from(err: SyncError) -> Self {
        match err {
            SyncError::Locked => Self::Locked,
            SyncError::Agent(err) => err,
            other => Self::Sync {
                message: other.to_string(),
            },
        }
    }
}

/// Registers this vault's account on `server` with an invite. Checks the
/// password against the local account record first.
pub fn register(
    record: &AccountRecord,
    server: &str,
    username: &str,
    invite: &str,
    password: &[u8],
    device_name: &str,
) -> Result<(SyncState, AccountKeys), SyncError> {
    let client = HttpClient::new(server)?;
    let username = sync::normalize_username(username)?;
    if !record.kdf.is_recommended_profile() {
        return Err(SyncError::Config(
            "this account's password hashing settings are not the recommended ones, \
             which the server requires"
                .to_owned(),
        ));
    }
    let master = record.kdf.derive(password)?;
    let keys = record.unlock_with(&master)?;
    let info = client.server_info()?;
    let reply = client.register(&RegisterRequest {
        invite: invite.trim().to_owned(),
        username: username.clone(),
        account: record.clone(),
        identity: keys.identity(),
        proof: sync::prove_registration(&keys, &username, &info.public_key)?,
        auth_key: master.server_auth_key(),
        device_name: device_name.to_owned(),
    })?;
    if reply.account.identity != keys.identity() {
        return Err(SyncError::Protocol(
            "the server registered different keys".to_owned(),
        ));
    }
    Ok((SyncState::new(client.base(), &reply), keys))
}

/// Logs in to an account on `server`, for a new device or again after a
/// logout. Returns the server's account record, checked by unlocking it with
/// `password`. If this machine already has an account, it must be the same one.
pub fn login(
    local: Option<&AccountRecord>,
    server: &str,
    username: &str,
    password: &[u8],
    device_name: &str,
) -> Result<(SyncState, AccountRecord, AccountKeys), SyncError> {
    let client = HttpClient::new(server)?;
    let username = sync::normalize_username(username)?;
    let kdf = client.prelogin(&username)?.kdf;
    // A server must not get to choose cheap hashing for the key we send back.
    kdf.check_minimum()?;
    let master = kdf.derive(password)?;
    let auth_key: AuthKey = master.server_auth_key();
    let reply = client.login(&LoginRequest {
        username,
        auth_key,
        device_name: device_name.to_owned(),
    })?;
    let session_client = HttpClient::new(server)?.with_token(&reply.token);
    let record = reply.account.account.clone();
    let checked = (|| {
        if record.kdf != kdf {
            return Err(SyncError::Protocol(
                "the account record does not match the login parameters".to_owned(),
            ));
        }
        let keys = record.unlock_with(&master).map_err(|_| {
            SyncError::Protocol(
                "the server's account record does not open with this password".to_owned(),
            )
        })?;
        if reply.account.identity != keys.identity() {
            return Err(SyncError::Protocol(
                "the server reports different keys for this account".to_owned(),
            ));
        }
        if let Some(local) = local
            && local.public_key != record.public_key
        {
            return Err(SyncError::Config(format!(
                "this machine already has a different account (fingerprint {}); \
                 move its SILO_HOME away to use {} here",
                local.public_key.fingerprint(),
                reply.account.username
            )));
        }
        Ok(keys)
    })();
    match checked {
        Ok(keys) => Ok((SyncState::new(client.base(), &reply), record, keys)),
        Err(err) => {
            let _ = session_client.logout();
            Err(err)
        }
    }
}

/// This machine's name, for the device list.
pub fn default_device_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname NUL-terminates
    // on success when the name fits, and we stop at the first NUL anyway.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    let name = if ok {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    } else {
        String::new()
    };
    let name = name.trim().trim_end_matches(".local");
    if name.is_empty() {
        "unnamed device".to_owned()
    } else {
        name.chars().take(64).collect()
    }
}
