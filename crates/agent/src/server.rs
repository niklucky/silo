//! The agent process: accepts connections on a Unix socket, one thread each,
//! and serves [`Request`]s against a shared, lockable [`Session`]. A
//! background thread syncs with the server while unlocked, if set up.

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use silo_core::AccountKeys;
use silo_core::sync::ErrorCode;

use crate::protocol::{AgentError, Reply, Request, Response, StatusInfo, SyncStatusInfo};
use crate::session::Session;
use crate::store::Store;
use crate::sync::{
    self, Baseline, HttpClient, SyncError, SyncReport, SyncState, Vault, VaultAccess,
};

/// How long a vault stays unlocked unless the client asks otherwise.
pub const DEFAULT_TTL: Duration = Duration::from_secs(12 * 60 * 60);
/// How often to sync while unlocked when nothing else prompts it.
pub const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);
const EXPIRY_CHECK_INTERVAL: Duration = Duration::from_secs(15);
/// Wait after a change before syncing, so a burst of changes goes up at once.
const SYNC_DEBOUNCE: Duration = Duration::from_secs(2);

pub struct Config {
    pub store: Store,
    pub default_ttl: Duration,
    /// Background sync period. `None` syncs only when asked (`silo sync`).
    pub sync_interval: Option<Duration>,
}

struct State {
    store: Store,
    session: Option<Session>,
    expires_at: Option<Instant>,
    default_ttl: Duration,
    sync: Option<SyncState>,
}

struct Shared {
    state: Mutex<State>,
    shutdown: AtomicBool,
    socket: PathBuf,
    /// Wakes the background sync thread, if there is one.
    nudge: Option<mpsc::Sender<()>>,
    /// Held for a whole sync run, so runs never overlap.
    syncing: Mutex<()>,
}

/// Runs the agent until a `shutdown` request arrives. Blocks the calling thread.
pub fn run(config: Config) -> io::Result<()> {
    let socket = config.store.paths().socket_file().to_path_buf();
    if socket.exists() {
        if UnixStream::connect(&socket).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "another agent is already listening",
            ));
        }
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    log(&format!("listening on {}", socket.display()));

    let sync = config
        .store
        .read_sync::<SyncState>()
        .map_err(io::Error::other)?;
    let (nudge, nudged) = match config.sync_interval {
        Some(_) => {
            let (tx, rx) = mpsc::channel();
            (Some(tx), Some(rx))
        }
        None => (None, None),
    };
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            store: config.store,
            session: None,
            expires_at: None,
            default_ttl: config.default_ttl,
            sync,
        }),
        shutdown: AtomicBool::new(false),
        socket: socket.clone(),
        nudge,
        syncing: Mutex::new(()),
    });
    if let (Some(interval), Some(nudged)) = (config.sync_interval, nudged) {
        let shared = Arc::clone(&shared);
        thread::spawn(move || sync_loop(&shared, &nudged, interval));
    }

    let expiry = Arc::clone(&shared);
    thread::spawn(move || {
        while !expiry.shutdown.load(Ordering::SeqCst) {
            thread::sleep(EXPIRY_CHECK_INTERVAL);
            if lock_state(&expiry).expire_if_needed() {
                log("auto-locked after ttl");
            }
        }
    });

    for stream in listener.incoming() {
        if shared.shutdown.load(Ordering::SeqCst) {
            break;
        }
        match stream {
            Ok(stream) => {
                let shared = Arc::clone(&shared);
                thread::spawn(move || handle(stream, &shared));
            }
            Err(err) => log(&format!("accept failed: {err}")),
        }
    }

    let _ = fs::remove_file(&socket);
    log("stopped");
    Ok(())
}

fn handle(stream: UnixStream, shared: &Shared) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let response = match serde_json::from_str::<Request>(line.trim_end()) {
            Ok(request) => dispatch(request, shared),
            Err(err) => Response::Err(AgentError::Invalid {
                message: err.to_string(),
            }),
        };
        line.zeroize();

        let mut out = serde_json::to_vec(&response).unwrap_or_else(|err| {
            serde_json::to_vec(&Response::Err(AgentError::Internal {
                message: err.to_string(),
            }))
            .expect("static error encodes")
        });
        out.push(b'\n');
        if writer
            .write_all(&out)
            .and_then(|()| writer.flush())
            .is_err()
        {
            break;
        }
        if shared.shutdown.load(Ordering::SeqCst) {
            // Wake the accept loop so `run` can return.
            let _ = UnixStream::connect(&shared.socket);
            break;
        }
    }
}

fn dispatch(request: Request, shared: &Shared) -> Response {
    // Requests that go to the sync server run without holding the state lock.
    let result = match request {
        Request::Sync => sync_now(shared)
            .map(Reply::Synced)
            .map_err(AgentError::from),
        Request::SyncRegister {
            server,
            username,
            invite,
            mut password,
            device_name,
        } => {
            let result = sync_register(shared, &server, &username, &invite, &password, device_name);
            password.zeroize();
            result.map_err(AgentError::from)
        }
        Request::SyncLogin {
            server,
            username,
            mut password,
            device_name,
        } => {
            let result = sync_login(shared, &server, &username, &password, device_name);
            password.zeroize();
            result.map_err(AgentError::from)
        }
        Request::SyncLogout => sync_logout(shared).map_err(AgentError::from),
        Request::SyncDevices => sync_client(shared)
            .and_then(|(client, _)| client.devices())
            .map(Reply::Devices)
            .map_err(AgentError::from),
        Request::SyncRevokeDevice { device_id } => {
            sync_revoke(shared, &device_id).map_err(AgentError::from)
        }
        other => return dispatch_locked(other, shared),
    };
    result.into()
}

fn dispatch_locked(request: Request, shared: &Shared) -> Response {
    let mut state = lock_state(shared);
    state.expire_if_needed();
    let result = match request {
        Request::Status => Ok(Reply::Status(state.status())),
        Request::Unlock {
            mut password,
            ttl_secs,
        } => {
            let result = state.unlock(password.as_bytes(), ttl_secs.map(Duration::from_secs));
            password.zeroize();
            if result.is_ok() {
                nudge(shared);
            }
            result
        }
        Request::Lock => {
            state.lock();
            log("locked by request");
            Ok(Reply::Locked)
        }
        Request::Shutdown => {
            state.lock();
            shared.shutdown.store(true, Ordering::SeqCst);
            log("shutdown requested");
            Ok(Reply::ShuttingDown)
        }
        Request::List(filter) => state
            .session()
            .map(|session| Reply::List(session.list(&filter))),
        Request::Get { selector } => state
            .session()
            .and_then(|session| session.get(&selector))
            .map(Reply::Secret),
        Request::Add(new) => {
            let now = crate::unix_now();
            let mut rng = rand::rng();
            let State { store, session, .. } = &mut *state;
            session
                .as_mut()
                .ok_or(AgentError::Locked)
                .and_then(|s| s.add(store, &mut rng, now, new))
                .map(Reply::Added)
                .inspect(|_| nudge(shared))
        }
        Request::Update(update) => {
            let now = crate::unix_now();
            let mut rng = rand::rng();
            let State { store, session, .. } = &mut *state;
            session
                .as_mut()
                .ok_or(AgentError::Locked)
                .and_then(|s| s.update(store, &mut rng, now, update))
                .map(Reply::Updated)
                .inspect(|_| nudge(shared))
        }
        Request::Remove { selector } => {
            let now = crate::unix_now();
            let State {
                store,
                session,
                sync,
                ..
            } = &mut *state;
            session
                .as_mut()
                .ok_or(AgentError::Locked)
                .and_then(|s| {
                    let removed = s.remove(store, &selector)?;
                    if let Some(sync) = sync {
                        sync::record_deletion(sync, s, removed.id, now);
                        store.write_sync(sync)?;
                    }
                    Ok(removed)
                })
                .map(Reply::Removed)
                .inspect(|_| nudge(shared))
        }
        Request::History { selector } => {
            let State { store, session, .. } = &mut *state;
            session
                .as_ref()
                .ok_or(AgentError::Locked)
                .and_then(|s| s.history(store, &selector))
                .map(Reply::History)
        }
        Request::Match { url, site } => state
            .session()
            .and_then(|session| session.matches(&url, site))
            .map(Reply::Matches),
        Request::Site { url } => silo_core::vault::Url::parse(&url)
            .map_err(|err| AgentError::Invalid {
                message: format!("invalid url {url:?}: {err}"),
            })
            .map(|target| {
                Reply::Site(
                    target
                        .host_str()
                        .and_then(silo_core::vault::registrable_domain),
                )
            }),
        Request::SyncStatus => Ok(Reply::SyncStatus(state.sync_status())),
        Request::Sync
        | Request::SyncRegister { .. }
        | Request::SyncLogin { .. }
        | Request::SyncLogout
        | Request::SyncDevices
        | Request::SyncRevokeDevice { .. } => unreachable!("handled in dispatch"),
    };
    result.into()
}

fn nudge(shared: &Shared) {
    if let Some(nudge) = &shared.nudge {
        let _ = nudge.send(());
    }
}

/// Syncs on every nudge (after a short pause) and every `interval`.
fn sync_loop(shared: &Shared, nudged: &mpsc::Receiver<()>, interval: Duration) {
    loop {
        match nudged.recv_timeout(interval) {
            Ok(()) => {
                thread::sleep(SYNC_DEBOUNCE);
                while nudged.try_recv().is_ok() {}
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        if shared.shutdown.load(Ordering::SeqCst) {
            return;
        }
        match sync_now(shared) {
            Ok(report) => log_report(&report),
            Err(SyncError::Locked | SyncError::NotConfigured) => {}
            Err(err) => log(&format!("sync failed: {err}")),
        }
    }
}

fn log_report(report: &SyncReport) {
    if report.pulled + report.removed + report.pushed > 0
        || !report.conflicts.is_empty()
        || !report.rejected.is_empty()
    {
        log(&format!(
            "synced: {} pulled, {} removed, {} pushed, {} conflicts, {} rejected",
            report.pulled,
            report.removed,
            report.pushed,
            report.conflicts.len(),
            report.rejected.len()
        ));
    }
    for line in report.conflicts.iter().chain(&report.rejected) {
        log(&format!("  {line}"));
    }
}

impl VaultAccess for Shared {
    fn with_vault<R>(
        &self,
        f: impl FnOnce(&mut Vault<'_>) -> Result<R, SyncError>,
    ) -> Result<R, SyncError> {
        let mut state = lock_state(self);
        state.expire_if_needed();
        let State {
            store,
            session,
            sync,
            ..
        } = &mut *state;
        let session = session.as_mut().ok_or(SyncError::Locked)?;
        let state = sync.as_mut().ok_or(SyncError::NotConfigured)?;
        f(&mut Vault {
            store,
            session,
            state,
        })
    }
}

fn sync_now(shared: &Shared) -> Result<SyncReport, SyncError> {
    let _running = shared
        .syncing
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    sync::run(shared, &crate::unix_now)
}

fn sync_register(
    shared: &Shared,
    server: &str,
    username: &str,
    invite: &str,
    password: &str,
    device_name: Option<String>,
) -> Result<Reply, SyncError> {
    let record = {
        let state = lock_state(shared);
        if let Some(sync) = &state.sync {
            return Err(SyncError::AlreadyConfigured(sync.server.clone()));
        }
        state.store.read_account()?
    };
    let device = device_name.unwrap_or_else(sync::default_device_name);
    let (sync_state, keys) = sync::register(
        &record,
        server,
        username,
        invite,
        password.as_bytes(),
        &device,
    )?;
    let mut state = lock_state(shared);
    state.start_syncing(sync_state, keys, false)?;
    let status = state.sync_status();
    drop(state);
    log("sync set up (registered)");
    nudge(shared);
    Ok(Reply::SyncStatus(status))
}

fn sync_login(
    shared: &Shared,
    server: &str,
    username: &str,
    password: &str,
    device_name: Option<String>,
) -> Result<Reply, SyncError> {
    let local = {
        let state = lock_state(shared);
        if let Some(sync) = &state.sync {
            return Err(SyncError::AlreadyConfigured(sync.server.clone()));
        }
        if state.store.has_account() {
            Some(state.store.read_account()?)
        } else {
            None
        }
    };
    let device = device_name.unwrap_or_else(sync::default_device_name);
    let (sync_state, record, keys) = sync::login(
        local.as_ref(),
        server,
        username,
        password.as_bytes(),
        &device,
    )?;
    let mut state = lock_state(shared);
    // A new machine gets the account; one whose password changed elsewhere
    // gets the record that opens with the new password.
    if local.as_ref() != Some(&record) {
        state.store.write_account(&record)?;
    }
    state.start_syncing(sync_state, keys, true)?;
    let status = state.sync_status();
    drop(state);
    log("sync set up (logged in)");
    nudge(shared);
    Ok(Reply::SyncStatus(status))
}

fn sync_logout(shared: &Shared) -> Result<Reply, SyncError> {
    let _running = shared
        .syncing
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let (client, _) = sync_client(shared)?;
    // Forget the server here even if it cannot be reached; the device can be
    // revoked from another one later.
    let revoked = match client.logout() {
        Ok(()) => true,
        Err(SyncError::Server {
            code: Some(ErrorCode::Unauthorized),
            ..
        }) => true,
        Err(err) => {
            log(&format!("logout: device not revoked on the server: {err}"));
            false
        }
    };
    let mut state = lock_state(shared);
    if let Some(sync) = &state.sync {
        state.store.write_sync_baseline(&sync.baseline())?;
    }
    state.store.delete_sync()?;
    state.sync = None;
    log("sync stopped (logged out)");
    Ok(Reply::LoggedOut { revoked })
}

fn sync_revoke(shared: &Shared, device_id: &str) -> Result<Reply, SyncError> {
    let (client, own) = sync_client(shared)?;
    if device_id == own {
        return Err(SyncError::Config(
            "that is this device; use `silo sync logout`".to_owned(),
        ));
    }
    client.revoke_device(device_id)?;
    Ok(Reply::DeviceRevoked)
}

/// An authenticated client for the configured server, and this device's id.
fn sync_client(shared: &Shared) -> Result<(HttpClient, String), SyncError> {
    let state = lock_state(shared);
    let sync = state.sync.as_ref().ok_or(SyncError::NotConfigured)?;
    Ok((
        HttpClient::new(&sync.server)?.with_token(&sync.token),
        sync.device_id.clone(),
    ))
}

fn lock_state(shared: &Shared) -> std::sync::MutexGuard<'_, State> {
    shared.state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl State {
    fn expire_if_needed(&mut self) -> bool {
        if let Some(expires_at) = self.expires_at
            && Instant::now() >= expires_at
        {
            self.lock();
            return true;
        }
        false
    }

    fn lock(&mut self) {
        self.session = None;
        self.expires_at = None;
    }

    fn unlock(&mut self, password: &[u8], ttl: Option<Duration>) -> Result<Reply, AgentError> {
        let (session, skipped) = Session::unlock(&self.store, password)?;
        if skipped > 0 {
            log(&format!(
                "warning: {skipped} stored secret(s) could not be opened with this account"
            ));
        }
        self.session = Some(session);
        self.expires_at = Some(Instant::now() + ttl.unwrap_or(self.default_ttl));
        log("unlocked");
        Ok(Reply::Unlocked(self.status()))
    }

    /// With `resume`, picks up what an earlier login to the same account
    /// left behind; a new registration starts from nothing.
    fn start_syncing(
        &mut self,
        mut sync: SyncState,
        keys: AccountKeys,
        resume: bool,
    ) -> Result<(), SyncError> {
        if self.session.is_none() {
            let (session, _) = Session::open(&self.store, keys)?;
            self.session = Some(session);
            self.expires_at = Some(Instant::now() + self.default_ttl);
            log("unlocked");
        }
        let session = self.session.as_ref().expect("opened above");
        if resume
            && let Some(baseline) = self.store.read_sync_baseline::<Baseline>()?
            && sync.resume(baseline)
        {
            // Secrets the server had that were deleted here while logged out.
            let now = crate::unix_now();
            let gone: Vec<_> = sync
                .known
                .keys()
                .filter(|id| session.stored(**id).is_none())
                .copied()
                .collect();
            for id in gone {
                sync::record_deletion(&mut sync, session, id, now);
            }
            log("sync resumed from the previous login");
        }
        self.store.write_sync(&sync)?;
        self.store.delete_sync_baseline()?;
        self.sync = Some(sync);
        Ok(())
    }

    fn sync_status(&self) -> Option<SyncStatusInfo> {
        let sync = self.sync.as_ref()?;
        let pending = self.session.as_ref().map(|session| {
            session
                .revisions()
                .iter()
                .filter(|(id, revision)| {
                    sync.known.get(id) != Some(revision)
                        && sync
                            .rejected
                            .get(id)
                            .is_none_or(|r| r.revision != *revision)
                })
                .count()
                + sync.deletes.len()
        });
        Some(SyncStatusInfo {
            server: sync.server.clone(),
            username: sync.username.clone(),
            device_id: sync.device_id.clone(),
            last_sync: sync.last_sync,
            last_error: sync.last_error.clone(),
            pending,
            rejected: sync
                .rejected
                .iter()
                .map(|(id, r)| {
                    let path = self
                        .session
                        .as_ref()
                        .and_then(|s| s.path_of(*id))
                        .unwrap_or_else(|| id.to_string());
                    format!("{path}: {}", r.message)
                })
                .collect(),
        })
    }

    fn session(&mut self) -> Result<&mut Session, AgentError> {
        self.session.as_mut().ok_or(AgentError::Locked)
    }

    fn status(&self) -> StatusInfo {
        StatusInfo {
            agent_version: crate::VERSION.to_owned(),
            core_version: silo_core::version().to_owned(),
            home: self.store.paths().home().display().to_string(),
            has_account: self.store.has_account(),
            unlocked: self.session.is_some(),
            fingerprint: self.session.as_ref().map(|s| s.fingerprint().to_string()),
            public_key: self.session.as_ref().map(|s| *s.public_key()),
            secrets: self.session.as_ref().map_or(0, Session::len),
            expires_in_secs: self
                .expires_at
                .map(|t| t.saturating_duration_since(Instant::now()).as_secs()),
        }
    }
}

fn log(message: &str) {
    let now = humantime::format_rfc3339_seconds(std::time::SystemTime::now());
    eprintln!("{now} {message}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use crate::paths::Paths;
    use crate::protocol::{ListFilter, NewSecret};
    use rand::SeedableRng;
    use silo_core::AccountRecord;
    use silo_core::crypto::KdfParams;
    use silo_core::vault::{FolderPath, Note, SecretBody};

    #[test]
    fn end_to_end_over_the_socket() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let store = Store::open(paths.clone()).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let kdf = KdfParams::new(&mut rng, 256, 1, 1);
        let (record, _) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();
        store.write_account(&record).unwrap();

        let server = thread::spawn(move || {
            run(Config {
                store,
                default_ttl: DEFAULT_TTL,
                sync_interval: None,
            })
        });
        let mut client = None;
        for _ in 0..100 {
            if let Ok(c) = Client::connect(paths.socket_file()) {
                client = Some(c);
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let mut client = client.expect("agent came up");

        match client.call(&Request::Status).unwrap() {
            Reply::Status(status) => assert!(!status.unlocked && status.has_account),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            client
                .call(&Request::List(ListFilter::default()))
                .unwrap_err()
                .to_string(),
            AgentError::Locked.to_string()
        );
        assert!(matches!(
            client.call(&Request::Unlock {
                password: "bad".into(),
                ttl_secs: None
            }),
            Err(crate::client::ClientError::Agent(AgentError::WrongPassword))
        ));
        match client
            .call(&Request::Unlock {
                password: "pw".into(),
                ttl_secs: Some(60),
            })
            .unwrap()
        {
            Reply::Unlocked(status) => {
                assert!(status.unlocked);
                assert!(status.expires_in_secs.unwrap() <= 60);
            }
            other => panic!("{other:?}"),
        }

        let new = NewSecret {
            title: "hello".into(),
            folder: FolderPath::parse("notes").unwrap(),
            tags: vec![],
            urls: vec![],
            basic_auth: false,
            body: SecretBody::Note(Note {
                text: "world".into(),
            }),
        };
        let Reply::Added(added) = client.call(&Request::Add(new)).unwrap() else {
            panic!()
        };
        assert_eq!(added.path(), "notes/hello");

        // A second connection sees the same session.
        let mut other = Client::connect(paths.socket_file()).unwrap();
        let Reply::Secret(view) = other
            .call(&Request::Get {
                selector: "hello".into(),
            })
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            view.body,
            SecretBody::Note(Note {
                text: "world".into()
            })
        );

        assert_eq!(client.call(&Request::Lock).unwrap(), Reply::Locked);
        assert!(matches!(
            other.call(&Request::Get {
                selector: "hello".into()
            }),
            Err(crate::client::ClientError::Agent(AgentError::Locked))
        ));
        assert_eq!(
            client.call(&Request::Shutdown).unwrap(),
            Reply::ShuttingDown
        );
        server.join().unwrap().unwrap();
        assert!(!paths.socket_file().exists());
    }
}
