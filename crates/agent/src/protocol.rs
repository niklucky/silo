//! Wire types. One JSON object per line in each direction.
//!
//! ```text
//! → {"method":"get","params":{"selector":"projects/api/dev-env"}}
//! ← {"ok":{"secret":{"id":"…","revision":1,"meta":{…},"body":{"env_set":{…}}}}}
//! ← {"err":{"code":"locked"}}
//! ```

use serde::{Deserialize, Serialize};
use silo_core::crypto::PublicKey;
use silo_core::sync::DeviceInfo;
use silo_core::vault::{FolderPath, SecretBody, SecretId, SecretKind, SecretMeta, Tag};

use crate::sync::SyncReport;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    Status,
    Unlock {
        password: String,
        /// Seconds until the agent locks itself again. Agent default if absent.
        #[serde(default)]
        ttl_secs: Option<u64>,
    },
    Lock,
    Shutdown,
    List(ListFilter),
    Get {
        selector: String,
    },
    Add(NewSecret),
    /// Replaces parts of a secret, making a new revision. The old revision is kept.
    Update(SecretUpdate),
    Remove {
        selector: String,
    },
    /// Earlier revisions of a secret, newest first.
    History {
        selector: String,
    },
    /// Logins whose URL patterns cover `url`, best match first.
    Match {
        url: String,
        /// Also logins saved for other hosts of the same site (`example.com`
        /// for `dev.example.com`), after the ones that match.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        site: bool,
    },
    /// The registrable domain of `url`'s host (`example.co.uk` for
    /// `a.b.example.co.uk`), or none for an address or a public suffix.
    Site {
        url: String,
    },
    /// Registers this vault's account on a sync server with an invite.
    SyncRegister {
        server: String,
        username: String,
        invite: String,
        password: String,
        #[serde(default)]
        device_name: Option<String>,
    },
    /// Logs this device in to a sync account. On a machine without an
    /// account, the account comes from the server.
    SyncLogin {
        server: String,
        username: String,
        password: String,
        #[serde(default)]
        device_name: Option<String>,
    },
    /// Revokes this device on the server and stops syncing. The vault stays.
    SyncLogout,
    /// Pulls and pushes now.
    Sync,
    SyncStatus,
    SyncDevices,
    SyncRevokeDevice {
        device_id: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListFilter {
    /// Restrict to this folder (and, unless `exact_folder`, everything beneath it).
    #[serde(default)]
    pub folder: Option<FolderPath>,
    #[serde(default)]
    pub exact_folder: bool,
    #[serde(default)]
    pub tag: Option<Tag>,
    #[serde(default)]
    pub kind: Option<SecretKind>,
}

/// Input for creating a secret. The agent assigns id, revision and timestamps.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NewSecret {
    pub title: String,
    #[serde(default)]
    pub folder: FolderPath,
    #[serde(default)]
    pub tags: Vec<Tag>,
    #[serde(default)]
    pub urls: Vec<String>,
    /// Logins only: answers HTTP Basic Auth on its URLs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub basic_auth: bool,
    pub body: SecretBody,
}

/// Changes to one secret. Absent fields keep their current value; a new body
/// must be of the same kind.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretUpdate {
    pub selector: String,
    /// The revision the change is based on. If the secret has moved on since,
    /// the update fails with [`AgentError::Stale`] instead of overwriting.
    #[serde(default)]
    pub revision: Option<u32>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub folder: Option<FolderPath>,
    #[serde(default)]
    pub tags: Option<Vec<Tag>>,
    #[serde(default)]
    pub urls: Option<Vec<String>>,
    /// Logins only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<bool>,
    #[serde(default)]
    pub body: Option<SecretBody>,
}

/// A secret without its body: what `list` returns.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretSummary {
    pub id: SecretId,
    pub revision: u32,
    pub meta: SecretMeta,
}

impl SecretSummary {
    /// `folder/title`, or just `title` at the root.
    pub fn path(&self) -> String {
        display_path(&self.meta)
    }
}

/// A fully decrypted secret: what `get` returns.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretView {
    pub id: SecretId,
    pub revision: u32,
    pub meta: SecretMeta,
    pub body: SecretBody,
}

impl SecretView {
    pub fn path(&self) -> String {
        display_path(&self.meta)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusInfo {
    pub agent_version: String,
    pub core_version: String,
    pub home: String,
    pub has_account: bool,
    pub unlocked: bool,
    pub fingerprint: Option<String>,
    pub public_key: Option<PublicKey>,
    pub secrets: usize,
    pub expires_in_secs: Option<u64>,
}

/// Where this vault syncs and how it went.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncStatusInfo {
    pub server: String,
    pub username: String,
    pub device_id: String,
    pub last_sync: Option<u64>,
    pub last_error: Option<String>,
    /// Local changes not on the server yet; unknown while locked.
    pub pending: Option<usize>,
    /// Changes the server refused, by `folder/title` or id.
    pub rejected: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reply {
    Status(StatusInfo),
    Unlocked(StatusInfo),
    Locked,
    ShuttingDown,
    List(Vec<SecretSummary>),
    Secret(SecretView),
    Added(SecretSummary),
    Updated(SecretSummary),
    Removed(SecretSummary),
    History(Vec<SecretView>),
    Matches(Vec<SecretSummary>),
    Site(Option<String>),
    SyncStatus(Option<SyncStatusInfo>),
    Synced(SyncReport),
    /// `revoked` is false if the server could not be reached.
    LoggedOut {
        revoked: bool,
    },
    Devices(Vec<DeviceInfo>),
    DeviceRevoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AgentError {
    #[error("vault is locked; run `silo unlock`")]
    Locked,
    #[error("wrong password")]
    WrongPassword,
    #[error("no account in {home}; run `silo init`")]
    NoAccount { home: String },
    #[error("no secret matches {selector:?}")]
    NotFound { selector: String },
    #[error("{selector:?} is ambiguous; matches: {}", matches.join(", "))]
    Ambiguous {
        selector: String,
        matches: Vec<String>,
    },
    #[error("{selector:?} changed since revision {expected}; it is now at revision {current}")]
    Stale {
        selector: String,
        expected: u32,
        current: u32,
    },
    #[error("invalid request: {message}")]
    Invalid { message: String },
    #[error("{message}")]
    Core { message: String },
    #[error("storage error: {message}")]
    Storage { message: String },
    #[error("sync: {message}")]
    Sync { message: String },
    #[error("internal error: {message}")]
    Internal { message: String },
}

impl From<silo_core::Error> for AgentError {
    fn from(err: silo_core::Error) -> Self {
        match err {
            silo_core::Error::Unlock => Self::WrongPassword,
            other => Self::Core {
                message: other.to_string(),
            },
        }
    }
}

impl From<crate::store::StoreError> for AgentError {
    fn from(err: crate::store::StoreError) -> Self {
        match err {
            crate::store::StoreError::NoAccount(home) => Self::NoAccount {
                home: home.display().to_string(),
            },
            other => Self::Storage {
                message: other.to_string(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Ok(Reply),
    Err(AgentError),
}

impl From<Result<Reply, AgentError>> for Response {
    fn from(result: Result<Reply, AgentError>) -> Self {
        match result {
            Ok(reply) => Self::Ok(reply),
            Err(err) => Self::Err(err),
        }
    }
}

impl From<Response> for Result<Reply, AgentError> {
    fn from(response: Response) -> Self {
        match response {
            Response::Ok(reply) => Ok(reply),
            Response::Err(err) => Err(err),
        }
    }
}

/// `folder/title`, or just `title` at the root.
pub fn display_path(meta: &SecretMeta) -> String {
    if meta.folder.is_root() {
        meta.title.clone()
    } else {
        format!("{}/{}", meta.folder, meta.title)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_shape() {
        let json = serde_json::to_string(&Request::Get {
            selector: "x".into(),
        })
        .unwrap();
        assert_eq!(json, r#"{"method":"get","params":{"selector":"x"}}"#);
        assert_eq!(
            serde_json::to_string(&Request::Status).unwrap(),
            r#"{"method":"status"}"#
        );
        let list: Request = serde_json::from_str(r#"{"method":"list","params":{}}"#).unwrap();
        assert_eq!(list, Request::List(ListFilter::default()));
        let plain = Request::Match {
            url: "https://x".into(),
            site: false,
        };
        let json = serde_json::to_string(&plain).unwrap();
        assert_eq!(json, r#"{"method":"match","params":{"url":"https://x"}}"#);
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), plain);
        let site: Request =
            serde_json::from_str(r#"{"method":"site","params":{"url":"https://x"}}"#).unwrap();
        assert_eq!(
            site,
            Request::Site {
                url: "https://x".into()
            }
        );
        assert_eq!(
            serde_json::to_string(&Response::Ok(Reply::Site(None))).unwrap(),
            r#"{"ok":{"site":null}}"#
        );
        let update: Request = serde_json::from_str(
            r#"{"method":"update","params":{"selector":"a","revision":2,"urls":["x.com"]}}"#,
        )
        .unwrap();
        let Request::Update(update) = update else {
            panic!("not an update")
        };
        assert_eq!(update.revision, Some(2));
        assert_eq!(update.urls, Some(vec!["x.com".to_owned()]));
        assert_eq!(update.title, None);
    }

    #[test]
    fn response_wire_shape() {
        assert_eq!(
            serde_json::to_string(&Response::Ok(Reply::Locked)).unwrap(),
            r#"{"ok":"locked"}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::Err(AgentError::Locked)).unwrap(),
            r#"{"err":{"code":"locked"}}"#
        );
        let err = Response::Err(AgentError::Ambiguous {
            selector: "a".into(),
            matches: vec!["x/a".into(), "y/a".into()],
        });
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(
            json,
            r#"{"err":{"code":"ambiguous","selector":"a","matches":["x/a","y/a"]}}"#
        );
        assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), err);
    }
}
