//! SQLite storage. One connection behind a mutex: writes are serialized
//! anyway, and a family-sized server never notices. Handlers reach it through
//! [`Db::run`] on a blocking thread.
//!
//! The schema is versioned with `PRAGMA user_version`; each entry in
//! [`MIGRATIONS`] moves it up by one.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use rand::Rng;
use rusqlite::{Connection, OptionalExtension, params};
use silo_core::sync::ServerKey;

use crate::error::{ApiError, ApiResult};

const MIGRATIONS: &[&str] = &[r#"
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

CREATE TABLE accounts (
    id             INTEGER PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    public_key     BLOB NOT NULL UNIQUE,
    signing_key    BLOB NOT NULL UNIQUE,
    record         TEXT NOT NULL,
    record_version INTEGER NOT NULL,
    auth_hash      BLOB NOT NULL,
    created_at     INTEGER NOT NULL
) STRICT;

CREATE TABLE invites (
    code_hash  BLOB PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_by    INTEGER REFERENCES accounts(id),
    used_at    INTEGER
) STRICT;

CREATE TABLE devices (
    id           TEXT PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   BLOB NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
) STRICT;

-- One row per pair of accounts, the smaller id first. Pending until the
-- account that did not ask accepts.
CREATE TABLE connections (
    low_id       INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    high_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    requested_by INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    accepted_at  INTEGER,
    PRIMARY KEY (low_id, high_id),
    CHECK (low_id < high_id)
) STRICT;

-- The current state of each secret. `seq` is a server-wide change counter:
-- every push that changes a row gives it the next number, and clients pull
-- rows with a `seq` above their cursor.
CREATE TABLE secrets (
    id               TEXT PRIMARY KEY,
    owner_id         INTEGER NOT NULL REFERENCES accounts(id),
    current_revision INTEGER NOT NULL,
    tombstone        TEXT,
    seq              INTEGER NOT NULL UNIQUE
) STRICT;

-- Every revision ever pushed, sealed as the client sent it.
CREATE TABLE revisions (
    secret_id  TEXT NOT NULL REFERENCES secrets(id),
    revision   INTEGER NOT NULL,
    author_id  INTEGER NOT NULL REFERENCES accounts(id),
    data       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (secret_id, revision)
) STRICT;

CREATE TABLE grants (
    secret_id TEXT NOT NULL,
    revision  INTEGER NOT NULL,
    recipient BLOB NOT NULL,
    data      TEXT NOT NULL,
    PRIMARY KEY (secret_id, revision, recipient),
    FOREIGN KEY (secret_id, revision) REFERENCES revisions(secret_id, revision)
) STRICT;

CREATE INDEX grants_by_recipient ON grants(recipient, secret_id, revision);
"#];

/// Key of the random secret that makes up KDF parameters for unknown usernames.
pub const PRELOGIN_SECRET: &str = "prelogin_secret";
/// Key of the server's static X25519 secret, for registration key proofs.
pub const SERVER_KEY: &str = "server_key";

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> anyhow::Result<Self> {
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        migrate(&mut conn)?;
        for key in [PRELOGIN_SECRET, SERVER_KEY] {
            let mut secret = [0u8; 32];
            rand::rng().fill_bytes(&mut secret);
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?1, ?2)",
                params![key, &secret[..]],
            )?;
        }
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// The server's static key, created with the database.
    pub fn server_key(&self) -> anyhow::Result<ServerKey> {
        let bytes = self
            .with(|conn| setting(conn, SERVER_KEY))
            .map_err(|err| anyhow::anyhow!(err.message))?
            .ok_or_else(|| anyhow::anyhow!("server key missing"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("server key has the wrong length"))?;
        Ok(ServerKey::from_bytes(bytes))
    }

    /// Runs `f` with the connection. Blocks; call from a blocking thread.
    pub fn with<T>(&self, f: impl FnOnce(&mut Connection) -> ApiResult<T>) -> ApiResult<T> {
        let mut conn = self.conn.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut conn)
    }

    /// Runs `f` on a blocking thread, for async handlers.
    pub async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> ApiResult<T> + Send + 'static,
    ) -> ApiResult<T> {
        let db = self.clone();
        tokio::task::spawn_blocking(move || db.with(f))
            .await
            .map_err(ApiError::internal)?
    }
}

fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    let version: usize = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > MIGRATIONS.len() {
        anyhow::bail!(
            "database schema version {version} is newer than this server ({}); upgrade silo-server",
            MIGRATIONS.len()
        );
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(version) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", i + 1)?;
        tx.commit()?;
    }
    Ok(())
}

pub fn setting(conn: &Connection, key: &str) -> ApiResult<Option<Vec<u8>>> {
    Ok(conn
        .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_once_and_keeps_the_prelogin_secret() {
        let dir = std::env::temp_dir().join(format!("silo-server-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.db");
        let _ = std::fs::remove_file(&path);

        let first = Db::open(&path).unwrap();
        let secret = first
            .with(|conn| setting(conn, PRELOGIN_SECRET))
            .unwrap()
            .unwrap();
        drop(first);

        let again = Db::open(&path).unwrap();
        let version: usize = again
            .with(|conn| Ok(conn.pragma_query_value(None, "user_version", |r| r.get(0))?))
            .unwrap();
        assert_eq!(version, MIGRATIONS.len());
        assert_eq!(
            again.with(|conn| setting(conn, PRELOGIN_SECRET)).unwrap(),
            Some(secret)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
