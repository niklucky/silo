//! On-disk layout. Every file is written atomically with mode 0600.
//!
//! ```text
//! <home>/account.json
//! <home>/sync.json                          sync settings, device token, progress
//! <home>/vault/<id>.json                    latest revision of each secret
//! <home>/vault/history/<id>/<revision>.json revisions replaced by an update
//! ```

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;
use silo_core::AccountRecord;
use silo_core::vault::SecretId;
pub use silo_core::vault::StoredSecret;

use crate::paths::Paths;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("no account in {0}; run `silo init`")]
    NoAccount(PathBuf),
}

pub struct Store {
    paths: Paths,
}

impl Store {
    /// Opens (creating if needed) the data directory with private permissions.
    pub fn open(paths: Paths) -> Result<Self, StoreError> {
        create_private_dir(paths.home())?;
        create_private_dir(&paths.vault_dir())?;
        create_private_dir(&paths.home().join("local-vault"))?;
        Ok(Self { paths })
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    pub fn has_account(&self) -> bool {
        self.paths.account_file().is_file()
    }

    pub fn read_account(&self) -> Result<AccountRecord, StoreError> {
        let path = self.paths.account_file();
        if !path.is_file() {
            return Err(StoreError::NoAccount(self.paths.home().to_path_buf()));
        }
        read_json(&path)
    }

    pub fn write_account(&self, record: &AccountRecord) -> Result<(), StoreError> {
        write_json(&self.paths.account_file(), record)
    }

    /// Sync settings, if this vault syncs with a server.
    pub fn read_sync<T: DeserializeOwned>(&self) -> Result<Option<T>, StoreError> {
        read_optional(&self.paths.sync_file())
    }

    pub fn write_sync<T: Serialize>(&self, state: &T) -> Result<(), StoreError> {
        write_json(&self.paths.sync_file(), state)
    }

    pub fn delete_sync(&self) -> Result<(), StoreError> {
        remove_optional(self.paths.sync_file())
    }

    /// What an earlier login left behind, if any.
    pub fn read_sync_baseline<T: DeserializeOwned>(&self) -> Result<Option<T>, StoreError> {
        read_optional(&self.paths.sync_baseline_file())
    }

    pub fn write_sync_baseline<T: Serialize>(&self, baseline: &T) -> Result<(), StoreError> {
        write_json(&self.paths.sync_baseline_file(), baseline)
    }

    pub fn delete_sync_baseline(&self) -> Result<(), StoreError> {
        remove_optional(self.paths.sync_baseline_file())
    }

    pub fn read_trust<T: DeserializeOwned>(&self) -> Result<Option<T>, StoreError> {
        read_optional(&self.paths.home().join("trust.json"))
    }

    pub fn write_trust<T: Serialize>(&self, trust: &T) -> Result<(), StoreError> {
        write_json(&self.paths.home().join("trust.json"), trust)
    }

    /// Undelivered recovery paths survive a failed sync, restart or logout.
    pub fn read_conflict_notices(&self) -> Result<Vec<String>, StoreError> {
        Ok(read_optional(&self.paths.home().join("conflict-notices.json"))?.unwrap_or_default())
    }

    pub fn write_conflict_notices(&self, notices: &[String]) -> Result<(), StoreError> {
        write_json(&self.paths.home().join("conflict-notices.json"), &notices)
    }

    /// Remove only notices delivered by this report. Callers serialize this
    /// with sync so an older response cannot clear a newer run's notices.
    pub fn acknowledge_conflict_notices(&self, delivered: &[String]) -> Result<(), StoreError> {
        if delivered.is_empty() {
            return Ok(());
        }
        let mut pending = self.read_conflict_notices()?;
        let before = pending.len();
        pending.retain(|notice| !delivered.contains(notice));
        if pending.len() == before {
            return Ok(());
        }
        if pending.is_empty() {
            remove_optional(self.paths.home().join("conflict-notices.json"))
        } else {
            self.write_conflict_notices(&pending)
        }
    }

    /// Loads the latest revision of every secret. Order is unspecified; callers sort.
    pub fn load_all(&self) -> Result<Vec<StoredSecret>, StoreError> {
        let mut paths = json_files(&self.paths.vault_dir())?;
        paths.extend(json_files(&self.paths.home().join("local-vault"))?);
        paths.iter().map(|path| read_json(path)).collect()
    }

    pub fn save(&self, stored: &StoredSecret) -> Result<(), StoreError> {
        write_json(&self.entry_path(stored.secret.id), stored)
    }

    /// Private records live outside the directory scanned by sync-only/older
    /// clients, so their absence from sync does not rely on a registry alone.
    pub fn save_local(&self, stored: &StoredSecret) -> Result<(), StoreError> {
        write_json(
            &self
                .paths
                .home()
                .join("local-vault")
                .join(format!("{}.json", stored.secret.id)),
            stored,
        )
    }

    pub fn is_local_only(&self, id: SecretId) -> bool {
        self.paths
            .home()
            .join("local-vault")
            .join(format!("{id}.json"))
            .is_file()
    }

    /// Removes a secret together with its history.
    pub fn delete(&self, id: SecretId) -> Result<(), StoreError> {
        let path = self.entry_path(id);
        let history = self.history_dir(id);
        fs::remove_file(&path).map_err(|source| StoreError::Io { path, source })?;
        if history.is_dir() {
            fs::remove_dir_all(&history).map_err(|source| StoreError::Io {
                path: history,
                source,
            })?;
        }
        Ok(())
    }

    /// Keeps a revision that is about to be replaced. It stays sealed as it was.
    pub fn archive(&self, stored: &StoredSecret) -> Result<(), StoreError> {
        let dir = self.history_dir(stored.secret.id);
        create_private_dir(dir.parent().expect("history has a parent"))?;
        create_private_dir(&dir)?;
        write_json(
            &dir.join(format!("{}.json", stored.secret.revision)),
            stored,
        )
    }

    /// Drops one revision from history, if it is there.
    pub fn unarchive(&self, id: SecretId, revision: u32) -> Result<(), StoreError> {
        remove_optional(self.history_dir(id).join(format!("{revision}.json")))
    }

    /// True if this revision of the secret is in history.
    pub fn has_archived(&self, id: SecretId, revision: u32) -> bool {
        self.history_dir(id)
            .join(format!("{revision}.json"))
            .is_file()
    }

    /// Earlier revisions of one secret, newest first.
    pub fn history(&self, id: SecretId) -> Result<Vec<StoredSecret>, StoreError> {
        let dir = self.history_dir(id);
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut out: Vec<StoredSecret> = Vec::new();
        for path in json_files(&dir)? {
            out.push(read_json(&path)?);
        }
        out.sort_by_key(|stored| std::cmp::Reverse(stored.secret.revision));
        Ok(out)
    }

    fn entry_path(&self, id: SecretId) -> PathBuf {
        if self.is_local_only(id) {
            return self
                .paths
                .home()
                .join("local-vault")
                .join(format!("{id}.json"));
        }
        self.paths.vault_dir().join(format!("{id}.json"))
    }

    fn history_dir(&self, id: SecretId) -> PathBuf {
        let private = self
            .paths
            .home()
            .join("local-vault")
            .join(HISTORY_DIR)
            .join(id.to_string());
        if self.is_local_only(id) || private.is_dir() {
            return private;
        }
        self.paths
            .vault_dir()
            .join(HISTORY_DIR)
            .join(id.to_string())
    }
}

const HISTORY_DIR: &str = "history";

fn read_optional<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, StoreError> {
    if !path.is_file() {
        return Ok(None);
    }
    read_json(path).map(Some)
}

fn remove_optional(path: PathBuf) -> Result<(), StoreError> {
    match fs::remove_file(&path) {
        Err(source) if source.kind() != io::ErrorKind::NotFound => {
            Err(StoreError::Io { path, source })
        }
        _ => Ok(()),
    }
}

/// The `*.json` files directly in `dir`.
fn json_files(dir: &Path) -> Result<Vec<PathBuf>, StoreError> {
    let io_err = |source| StoreError::Io {
        path: dir.to_path_buf(),
        source,
    };
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(io_err)? {
        let path = entry.map_err(io_err)?.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "json") {
            out.push(path);
        }
    }
    Ok(out)
}

fn create_private_dir(path: &Path) -> Result<(), StoreError> {
    let io_err = |source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    };
    if !path.is_dir() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(io_err)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_err)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, StoreError> {
    let bytes = fs::read(path).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| StoreError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|source| StoreError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    write_private(path, &bytes).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Writes to a sibling temp file with mode 0600, then renames over `path`.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use silo_core::crypto::KdfParams;
    use silo_core::vault::SecretKind;
    use silo_core::vault::{FolderPath, Note, SealedSecret, SecretBody, SecretMeta};

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn creates_private_directories_and_files() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("home"));
        let store = Store::open(paths.clone()).unwrap();
        assert_eq!(mode(paths.home()), 0o700);
        assert_eq!(mode(&paths.vault_dir()), 0o700);
        assert!(!store.has_account());
        assert!(matches!(
            store.read_account(),
            Err(StoreError::NoAccount(_))
        ));

        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let kdf = KdfParams::new(&mut rng, 256, 1, 1);
        let (record, _) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();
        store.write_account(&record).unwrap();
        assert!(store.has_account());
        assert_eq!(mode(&paths.account_file()), 0o600);
        assert_eq!(store.read_account().unwrap(), record);
        assert!(!paths.home().join("account.json.tmp").exists());
    }

    #[test]
    fn an_older_delivery_acknowledgment_keeps_newer_notices() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(Paths::new(dir.path())).unwrap();
        let first = "api/dev: private conflict copy id first".to_owned();
        let second = "api/dev: private conflict copy id second".to_owned();
        store
            .write_conflict_notices(std::slice::from_ref(&first))
            .unwrap();
        let sent = store.read_conflict_notices().unwrap();
        // A later sync adds another recovery path while the older response is
        // still being delivered on its socket.
        store
            .write_conflict_notices(&[first, second.clone()])
            .unwrap();
        store.acknowledge_conflict_notices(&sent).unwrap();
        let reopened = Store::open(Paths::new(dir.path())).unwrap();
        assert_eq!(
            reopened.read_conflict_notices().unwrap().as_slice(),
            std::slice::from_ref(&second)
        );
        reopened.acknowledge_conflict_notices(&sent).unwrap();
        assert_eq!(
            reopened.read_conflict_notices().unwrap().as_slice(),
            std::slice::from_ref(&second)
        );
        reopened.acknowledge_conflict_notices(&[second]).unwrap();
        assert!(reopened.read_conflict_notices().unwrap().is_empty());
    }

    #[test]
    fn save_load_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(Paths::new(dir.path())).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);

        let meta = SecretMeta {
            title: "n".into(),
            kind: SecretKind::Note,
            folder: FolderPath::root(),
            tags: vec![],
            urls: vec![],
            basic_auth: false,
            created_at: 0,
            updated_at: 0,
        };
        let body = SecretBody::Note(Note { text: "hi".into() });
        let kdf = KdfParams::new(&mut rng, 256, 1, 1);
        let (_, keys) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();
        let id = SecretId::from_random_bytes([1; 16]);
        let (sealed, _) = SealedSecret::seal(&mut rng, &keys, id, 1, &meta, &body).unwrap();
        let stored = StoredSecret {
            secret: sealed,
            grants: vec![],
        };

        assert!(store.load_all().unwrap().is_empty());
        store.save(&stored).unwrap();
        assert_eq!(store.load_all().unwrap(), vec![stored.clone()]);

        // An update archives the old revision; it is not loaded as a secret.
        assert!(store.history(id).unwrap().is_empty());
        store.archive(&stored).unwrap();
        let (second, _) = SealedSecret::seal(&mut rng, &keys, id, 2, &meta, &body).unwrap();
        let newer = StoredSecret {
            secret: second,
            grants: vec![],
        };
        store.archive(&newer).unwrap();
        assert_eq!(store.load_all().unwrap(), vec![stored.clone()]);
        let history = store.history(id).unwrap();
        assert_eq!(
            history
                .iter()
                .map(|s| s.secret.revision)
                .collect::<Vec<_>>(),
            [2, 1]
        );
        assert_eq!(
            mode(&dir.path().join("vault/history").join(id.to_string())),
            0o700
        );

        store.delete(id).unwrap();
        assert!(store.load_all().unwrap().is_empty());
        assert!(store.history(id).unwrap().is_empty());
        assert!(store.delete(id).is_err());
    }
}
