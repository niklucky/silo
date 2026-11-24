//! The agent process: accepts connections on a Unix socket, one thread each,
//! and serves [`Request`]s against a shared, lockable [`Session`]. A
//! background thread syncs with the server while unlocked, if set up.

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use rand::Rng;
use zeroize::{Zeroize, Zeroizing};

use silo_core::crypto::KEY_LEN;
use silo_core::sync::ErrorCode;
use silo_core::{AccountKeys, AccountRecord};

use crate::biometric::{BIOMETRIC_CONTEXT, BiometricError, BiometricProvider, BiometricRecord};
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
    /// Incremented on every lock so an in-flight biometric prompt cannot reopen
    /// the vault after an explicit lock.
    lock_epoch: u64,
}

struct Shared {
    state: Mutex<State>,
    shutdown: AtomicBool,
    socket: PathBuf,
    /// Wakes the background sync thread, if there is one.
    nudge: Option<mpsc::Sender<()>>,
    /// Held for a whole sync run, so runs never overlap.
    syncing: Mutex<()>,
    biometric: Arc<dyn BiometricProvider>,
    /// Held while a biometric operation is active so prompts and disable serialize.
    biometric_busy: Mutex<()>,
    /// Per-run secret written to `$SILO_HOME/agent.token` (0600) to authorize
    /// local management requests that sandboxed browser bridges cannot access.
    admin_token: Zeroizing<String>,
}

/// Runs the agent until a `shutdown` request arrives. Blocks the calling thread.
pub fn run(config: Config) -> io::Result<()> {
    run_with_biometric(config, crate::biometric::system_provider())
}

/// Like [`run`], with an explicit biometric provider (used in tests).
pub fn run_with_biometric(config: Config, biometric: Arc<dyn BiometricProvider>) -> io::Result<()> {
    // Hold an exclusive lock on SILO_HOME so two agents cannot share one vault
    // directory via different SILO_AGENT_SOCKET values (protecting agent.token
    // and biometric.json from concurrent writers).
    let home_lock_path = config.store.paths().home().join(".home.lock");
    let home_lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&home_lock_path)?;
    home_lock.try_lock().map_err(|err| match err {
        fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::AddrInUse,
            "another agent is already running for this vault",
        ),
        fs::TryLockError::Error(err) => err,
    })?;
    let home_meta = home_lock.metadata()?;
    let socket = config.store.paths().socket_file().to_path_buf();
    // Starting the desktop and CLI together must not let either agent remove
    // a socket the other agent just bound.
    let mut lock_path = socket.clone().into_os_string();
    lock_path.push(".lock");
    let socket_lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)?;
    let socket_meta = socket_lock.metadata()?;
    let _socket_lock =
        if (socket_meta.dev(), socket_meta.ino()) != (home_meta.dev(), home_meta.ino()) {
            socket_lock.try_lock().map_err(|err| match err {
                fs::TryLockError::WouldBlock => io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another agent is already listening",
                ),
                fs::TryLockError::Error(err) => err,
            })?;
            Some(socket_lock)
        } else {
            None
        };
    if let Ok(meta) = fs::symlink_metadata(&socket) {
        if !meta.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", socket.display()),
            ));
        }
        if UnixStream::connect(&socket).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "another agent is already listening",
            ));
        }
        fs::remove_file(&socket)?;
    }
    let token_path = config.store.paths().admin_token_file();
    let admin_token = write_admin_token(&token_path)?;

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
            lock_epoch: 0,
        }),
        shutdown: AtomicBool::new(false),
        socket: socket.clone(),
        nudge,
        syncing: Mutex::new(()),
        biometric,
        biometric_busy: Mutex::new(()),
        admin_token,
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

    // Drain any in-flight biometric operation before removing files and
    // dropping home_lock so a replacement agent cannot race with it.
    let _biometric_drain = shared.biometric_busy.lock();
    let _ = fs::remove_file(&socket);
    let _ = fs::remove_file(&token_path);
    drop(_biometric_drain);
    drop(home_lock);
    log("stopped");
    Ok(())
}

fn write_admin_token(path: &std::path::Path) -> io::Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(bytes.as_mut());
    let token = Zeroizing::new(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(token.as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|err| err.error)?;
    Ok(token)
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
    // Requests that do network IO or OS biometric/LocalAuthentication calls run
    // without holding the vault state lock.
    let result = match request {
        Request::Status => {
            let biometric_available = shared.biometric.is_available();
            let mut state = lock_state(shared);
            state.expire_if_needed();
            Ok(Reply::Status(state.status(biometric_available)))
        }
        Request::Unlock {
            mut password,
            ttl_secs,
        } => {
            let biometric_available = shared.biometric.is_available();
            let mut state = lock_state(shared);
            state.expire_if_needed();
            let result = state.unlock(
                password.as_bytes(),
                ttl_secs.map(Duration::from_secs),
                biometric_available,
            );
            password.zeroize();
            drop(state);
            if result.is_ok() {
                nudge(shared);
            }
            result
        }
        Request::UnlockBiometric { ttl_secs } => {
            unlock_biometric(shared, ttl_secs.map(Duration::from_secs))
        }
        Request::BiometricEnable { mut token } => {
            let result = biometric_enable(shared, &token);
            token.zeroize();
            result
        }
        Request::BiometricDisable { mut token } => {
            let result = biometric_disable(shared, &token);
            token.zeroize();
            result
        }
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
        Request::Status
        | Request::Unlock { .. }
        | Request::UnlockBiometric { .. }
        | Request::BiometricEnable { .. }
        | Request::BiometricDisable { .. }
        | Request::Sync
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
    if let Err(err) = state.accept_login_account(local.as_ref(), &record) {
        drop(state);
        // The server has already registered this device. Discard it when
        // another client completed setup while this login was in flight.
        let _ = HttpClient::new(&sync_state.server)
            .and_then(|client| client.with_token(&sync_state.token).logout());
        return Err(err);
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

fn require_admin_token(shared: &Shared, provided: &str) -> Result<(), AgentError> {
    let expected = shared.admin_token.as_bytes();
    let got = provided.as_bytes();
    let diff = expected
        .iter()
        .zip(got.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if expected.len() == got.len() && diff == 0 {
        Ok(())
    } else {
        Err(AgentError::Invalid {
            message: "this method requires local agent authorization".to_owned(),
        })
    }
}

fn map_biometric_error(err: BiometricError) -> AgentError {
    match err {
        BiometricError::Cancelled => AgentError::BiometricCancelled,
        other => AgentError::Biometric {
            message: other.to_string(),
        },
    }
}

fn unlock_biometric(shared: &Shared, ttl: Option<Duration>) -> Result<Reply, AgentError> {
    let Ok(_prompt_guard) = shared.biometric_busy.try_lock() else {
        return Err(AgentError::Biometric {
            message: "a biometric prompt is already open".to_owned(),
        });
    };
    if shared.shutdown.load(Ordering::SeqCst) {
        return Err(AgentError::Biometric {
            message: "agent is shutting down".to_owned(),
        });
    }
    let (account, bio, lock_epoch) = {
        let mut state = lock_state(shared);
        state.expire_if_needed();
        // Validate TTL before showing an OS prompt so an overflow fails fast.
        let _ = resolve_expiry(ttl, state.default_ttl)?;
        let account = state.store.read_account()?;
        let bio = state
            .store
            .read_biometric::<BiometricRecord>()?
            .ok_or_else(|| AgentError::Biometric {
                message: "biometric unlock is not enabled for this vault".to_owned(),
            })?;
        if bio.slot.public_key != account.public_key {
            return Err(AgentError::Biometric {
                message: "biometric unlock does not match this account; re-enable it".to_owned(),
            });
        }
        (account, bio, state.lock_epoch)
    };
    if !shared.biometric.is_available() {
        return Err(AgentError::Biometric {
            message: "biometric unlock is not available on this device".to_owned(),
        });
    }
    shared
        .biometric
        .authenticate("unlock your Silo vault")
        .map_err(map_biometric_error)?;
    let wrapping_key = shared
        .biometric
        .load_key(&bio.key_id)
        .map_err(map_biometric_error)?;
    let keys = bio
        .slot
        .open(&wrapping_key, &account.public_key, BIOMETRIC_CONTEXT)
        .map_err(|_| AgentError::Biometric {
            message: "biometric unlock key did not open this vault; disable and re-enable it"
                .to_owned(),
        })?;
    drop(wrapping_key);

    let biometric_available = shared.biometric.is_available();
    let mut state = lock_state(shared);
    if state.lock_epoch != lock_epoch {
        return Err(AgentError::BiometricCancelled);
    }
    let reply = state.unlock_with_keys(keys, ttl, biometric_available)?;
    drop(state);
    nudge(shared);
    Ok(reply)
}

fn biometric_enable(shared: &Shared, token: &str) -> Result<Reply, AgentError> {
    require_admin_token(shared, token)?;
    let Ok(_prompt_guard) = shared.biometric_busy.try_lock() else {
        return Err(AgentError::Biometric {
            message: "a biometric prompt is already open".to_owned(),
        });
    };
    if shared.shutdown.load(Ordering::SeqCst) {
        return Err(AgentError::Biometric {
            message: "agent is shutting down".to_owned(),
        });
    }
    {
        let mut state = lock_state(shared);
        state.expire_if_needed();
        if state.session.is_none() {
            return Err(AgentError::Locked);
        }
        if state.store.read_biometric::<BiometricRecord>()?.is_some() {
            return Err(AgentError::Invalid {
                message: "biometric unlock is already enabled; disable it first".to_owned(),
            });
        }
    }
    if !shared.biometric.is_available() {
        return Err(AgentError::Biometric {
            message: "biometric unlock is not available on this device".to_owned(),
        });
    }
    shared
        .biometric
        .authenticate("enable Touch ID unlock for Silo")
        .map_err(map_biometric_error)?;

    let mut rng = rand::rng();
    let mut wrapping_key = Zeroizing::new([0u8; KEY_LEN]);
    rng.fill_bytes(wrapping_key.as_mut());
    let mut id_bytes = [0u8; 16];
    rng.fill_bytes(&mut id_bytes);
    let key_id: String = id_bytes.iter().map(|b| format!("{b:02x}")).collect();

    let slot = {
        let mut state = lock_state(shared);
        state.expire_if_needed();
        if state.store.read_biometric::<BiometricRecord>()?.is_some() {
            return Err(AgentError::Invalid {
                message: "biometric unlock is already enabled; disable it first".to_owned(),
            });
        }
        let session = state.session.as_ref().ok_or(AgentError::Locked)?;
        session.seal_slot(&mut rng, &wrapping_key, BIOMETRIC_CONTEXT)?
    };

    shared
        .biometric
        .store_key(&key_id, &wrapping_key)
        .map_err(map_biometric_error)?;
    drop(wrapping_key);

    let biometric_available = shared.biometric.is_available();
    let record = BiometricRecord { key_id, slot };
    let status = {
        let mut state = lock_state(shared);
        state.expire_if_needed();
        if shared.shutdown.load(Ordering::SeqCst) || state.session.is_none() {
            drop(state);
            let _ = shared.biometric.delete_key(&record.key_id);
            return Err(AgentError::Locked);
        }
        if let Err(err) = state.store.write_biometric(&record) {
            drop(state);
            let _ = shared.biometric.delete_key(&record.key_id);
            return Err(err.into());
        }
        state.status(biometric_available)
    };
    log("biometric unlock enabled");
    Ok(Reply::Status(status))
}

fn biometric_disable(shared: &Shared, token: &str) -> Result<Reply, AgentError> {
    require_admin_token(shared, token)?;
    let _prompt_guard = shared
        .biometric_busy
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if shared.shutdown.load(Ordering::SeqCst) {
        return Err(AgentError::Biometric {
            message: "agent is shutting down".to_owned(),
        });
    }
    let old_key_id = {
        let mut state = lock_state(shared);
        state.expire_if_needed();
        state
            .store
            .read_biometric::<BiometricRecord>()?
            .map(|r| r.key_id)
    };
    if let Some(old) = old_key_id {
        shared
            .biometric
            .delete_key(&old)
            .map_err(map_biometric_error)?;
    }
    let biometric_available = shared.biometric.is_available();
    let status = {
        let mut state = lock_state(shared);
        state.expire_if_needed();
        state.store.delete_biometric()?;
        state.status(biometric_available)
    };
    log("biometric unlock disabled");
    Ok(Reply::Status(status))
}

fn lock_state(shared: &Shared) -> std::sync::MutexGuard<'_, State> {
    shared.state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl State {
    fn accept_login_account(
        &self,
        previous: Option<&AccountRecord>,
        record: &AccountRecord,
    ) -> Result<(), SyncError> {
        if let Some(sync) = &self.sync {
            return Err(SyncError::AlreadyConfigured(sync.server.clone()));
        }
        // A new machine gets the account. An existing one can receive a
        // newer record for that same account, as long as it hasn't changed
        // while the login was in flight.
        match previous {
            None => self.store.create_account(record)?,
            Some(previous) => {
                if self.store.read_account()? != *previous {
                    return Err(SyncError::Config(
                        "the local account changed during sign-in; try again".to_owned(),
                    ));
                }
                if previous != record {
                    self.store.write_account(record)?;
                }
            }
        }
        Ok(())
    }

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
        self.lock_epoch = self.lock_epoch.wrapping_add(1);
    }

    fn unlock(
        &mut self,
        password: &[u8],
        ttl: Option<Duration>,
        biometric_available: bool,
    ) -> Result<Reply, AgentError> {
        let (session, skipped) = Session::unlock(&self.store, password)?;
        self.finish_unlock(session, skipped, ttl, biometric_available)
    }

    fn unlock_with_keys(
        &mut self,
        keys: AccountKeys,
        ttl: Option<Duration>,
        biometric_available: bool,
    ) -> Result<Reply, AgentError> {
        let (session, skipped) = Session::open(&self.store, keys)?;
        self.finish_unlock(session, skipped, ttl, biometric_available)
    }

    fn finish_unlock(
        &mut self,
        session: Session,
        skipped: usize,
        ttl: Option<Duration>,
        biometric_available: bool,
    ) -> Result<Reply, AgentError> {
        let expires_at = resolve_expiry(ttl, self.default_ttl)?;
        if skipped > 0 {
            log(&format!(
                "warning: {skipped} stored secret(s) could not be opened with this account"
            ));
        }
        self.session = Some(session);
        self.expires_at = Some(expires_at);
        log("unlocked");
        Ok(Reply::Unlocked(self.status(biometric_available)))
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

    fn status(&self, biometric_available: bool) -> StatusInfo {
        let has_account = self.store.has_account();
        let biometric_enabled = has_account
            && self
                .store
                .read_account()
                .ok()
                .zip(
                    self.store
                        .read_biometric::<BiometricRecord>()
                        .ok()
                        .flatten(),
                )
                .is_some_and(|(account, bio)| bio.slot.public_key == account.public_key);
        StatusInfo {
            agent_version: crate::VERSION.to_owned(),
            core_version: silo_core::version().to_owned(),
            home: self.store.paths().home().display().to_string(),
            setup_home: self
                .store
                .paths()
                .home()
                .canonicalize()
                .ok()
                .map(PathBuf::into_os_string),
            has_account,
            unlocked: self.session.is_some(),
            fingerprint: self.session.as_ref().map(|s| s.fingerprint().to_string()),
            public_key: self.session.as_ref().map(|s| *s.public_key()),
            secrets: self.session.as_ref().map_or(0, Session::len),
            expires_in_secs: self
                .expires_at
                .map(|t| t.saturating_duration_since(Instant::now()).as_secs()),
            biometric_available,
            biometric_enabled,
        }
    }
}

fn resolve_expiry(ttl: Option<Duration>, default_ttl: Duration) -> Result<Instant, AgentError> {
    Instant::now()
        .checked_add(ttl.unwrap_or(default_ttl))
        .ok_or_else(|| AgentError::Invalid {
            message: "unlock ttl is too large".to_owned(),
        })
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

    #[test]
    fn biometric_enable_unlock_cancel_and_disable() {
        use std::collections::HashMap;
        use std::sync::Barrier;
        use std::sync::atomic::AtomicUsize;

        struct MockBiometric {
            available: AtomicBool,
            cancel_next: AtomicBool,
            fail_delete_next: AtomicBool,
            prompts: AtomicUsize,
            availability_checks: AtomicUsize,
            keys: Mutex<HashMap<String, [u8; KEY_LEN]>>,
            gate: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
        }

        impl MockBiometric {
            fn new() -> Self {
                Self {
                    available: AtomicBool::new(true),
                    cancel_next: AtomicBool::new(false),
                    fail_delete_next: AtomicBool::new(false),
                    prompts: AtomicUsize::new(0),
                    availability_checks: AtomicUsize::new(0),
                    keys: Mutex::new(HashMap::new()),
                    gate: Mutex::new(None),
                }
            }

            fn pause_next_prompt(&self) -> (Arc<Barrier>, Arc<Barrier>) {
                let entered = Arc::new(Barrier::new(2));
                let release = Arc::new(Barrier::new(2));
                *self.gate.lock().unwrap() = Some((Arc::clone(&entered), Arc::clone(&release)));
                (entered, release)
            }
        }

        impl BiometricProvider for MockBiometric {
            fn is_available(&self) -> bool {
                self.availability_checks.fetch_add(1, Ordering::SeqCst);
                self.available.load(Ordering::SeqCst)
            }

            fn authenticate(&self, _reason: &str) -> Result<(), BiometricError> {
                self.prompts.fetch_add(1, Ordering::SeqCst);
                if let Some((entered, release)) = self.gate.lock().unwrap().take() {
                    entered.wait();
                    release.wait();
                }
                if self.cancel_next.swap(false, Ordering::SeqCst) {
                    return Err(BiometricError::Cancelled);
                }
                Ok(())
            }

            fn store_key(&self, account: &str, key: &[u8; KEY_LEN]) -> Result<(), BiometricError> {
                self.keys.lock().unwrap().insert(account.to_owned(), *key);
                Ok(())
            }

            fn load_key(&self, account: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, BiometricError> {
                self.keys
                    .lock()
                    .unwrap()
                    .get(account)
                    .copied()
                    .map(Zeroizing::new)
                    .ok_or(BiometricError::KeyNotFound)
            }

            fn delete_key(&self, account: &str) -> Result<(), BiometricError> {
                if self.fail_delete_next.swap(false, Ordering::SeqCst) {
                    return Err(BiometricError::Failed("keychain locked".to_owned()));
                }
                self.keys.lock().unwrap().remove(account);
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let store = Store::open(paths.clone()).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        let kdf = KdfParams::new(&mut rng, 256, 1, 1);
        let (record, _) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();
        store.write_account(&record).unwrap();

        let mock = Arc::new(MockBiometric::new());
        let provider: Arc<dyn BiometricProvider> = Arc::clone(&mock) as _;
        let server = thread::spawn(move || {
            run_with_biometric(
                Config {
                    store,
                    default_ttl: DEFAULT_TTL,
                    sync_interval: None,
                },
                provider,
            )
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
        let token = fs::read_to_string(paths.admin_token_file()).unwrap();

        // A second agent for the same SILO_HOME on a different socket must be refused (S13).
        let second_paths = paths.clone().with_socket(dir.path().join("other.sock"));
        let second_store = Store::open(second_paths).unwrap();
        let err = run_with_biometric(
            Config {
                store: second_store,
                default_ttl: DEFAULT_TTL,
                sync_interval: None,
            },
            Arc::clone(&mock) as _,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);

        // Initially available but not enabled.
        let Reply::Status(status) = client.call(&Request::Status).unwrap() else {
            panic!()
        };
        assert!(status.biometric_available);
        assert!(!status.biometric_enabled);

        // Unauthorized biometric management is refused even on the raw socket (S1).
        assert!(matches!(
            client.call(&Request::BiometricEnable {
                token: String::new()
            }),
            Err(crate::client::ClientError::Agent(
                AgentError::Invalid { .. }
            ))
        ));
        assert!(matches!(
            client.call(&Request::BiometricDisable {
                token: "wrong".into()
            }),
            Err(crate::client::ClientError::Agent(
                AgentError::Invalid { .. }
            ))
        ));

        // Cannot enable while locked.
        assert!(matches!(
            client.call(&Request::BiometricEnable {
                token: token.clone()
            }),
            Err(crate::client::ClientError::Agent(AgentError::Locked))
        ));

        // Unlock with master password, add a secret, then enable biometrics.
        client
            .call(&Request::Unlock {
                password: "pw".into(),
                ttl_secs: None,
            })
            .unwrap();
        let before = mock.availability_checks.load(Ordering::SeqCst);
        client
            .call(&Request::Add(NewSecret {
                title: "bio-note".into(),
                folder: FolderPath::default(),
                tags: vec![],
                urls: vec![],
                basic_auth: false,
                body: SecretBody::Note(Note {
                    text: "opened via touch id".into(),
                }),
            }))
            .unwrap();
        let _ = client.call(&Request::List(ListFilter::default())).unwrap();
        let _ = client
            .call(&Request::Get {
                selector: "bio-note".into(),
            })
            .unwrap();
        // Ordinary vault operations do not probe LocalAuthentication (S9).
        assert_eq!(mock.availability_checks.load(Ordering::SeqCst), before);

        let Reply::Status(status) = client
            .call(&Request::BiometricEnable {
                token: token.clone(),
            })
            .unwrap()
        else {
            panic!()
        };
        assert!(status.biometric_enabled);
        assert_eq!(mock.keys.lock().unwrap().len(), 1);

        // Lock, then cancel a biometric unlock attempt: vault stays locked.
        client.call(&Request::Lock).unwrap();
        mock.cancel_next.store(true, Ordering::SeqCst);
        assert!(matches!(
            client.call(&Request::UnlockBiometric { ttl_secs: None }),
            Err(crate::client::ClientError::Agent(
                AgentError::BiometricCancelled
            ))
        ));
        let Reply::Status(status) = client.call(&Request::Status).unwrap() else {
            panic!()
        };
        assert!(!status.unlocked);

        // An explicit lock while a Touch ID prompt is pending must keep the vault locked (S2).
        let (entered, release) = mock.pause_next_prompt();
        let sock = paths.socket_file().to_path_buf();
        let pending = thread::spawn(move || {
            let mut c = Client::connect(&sock).unwrap();
            c.call(&Request::UnlockBiometric { ttl_secs: None })
        });
        entered.wait();
        client.call(&Request::Lock).unwrap();
        release.wait();
        assert!(matches!(
            pending.join().unwrap(),
            Err(crate::client::ClientError::Agent(
                AgentError::BiometricCancelled
            ))
        ));
        let Reply::Status(status) = client.call(&Request::Status).unwrap() else {
            panic!()
        };
        assert!(!status.unlocked);

        // Now unlock with biometrics and verify secrets decrypt.
        let Reply::Unlocked(status) = client
            .call(&Request::UnlockBiometric { ttl_secs: Some(90) })
            .unwrap()
        else {
            panic!()
        };
        assert!(status.unlocked);
        assert!(status.biometric_enabled);
        assert!(status.expires_in_secs.unwrap() <= 90);
        let Reply::Secret(view) = client
            .call(&Request::Get {
                selector: "bio-note".into(),
            })
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            view.body,
            SecretBody::Note(Note {
                text: "opened via touch id".into(),
            })
        );

        // Re-enrolling while already enabled is refused until disabled (S11/S13).
        assert!(matches!(
            client.call(&Request::BiometricEnable {
                token: token.clone()
            }),
            Err(crate::client::ClientError::Agent(
                AgentError::Invalid { .. }
            ))
        ));

        // Disable first, then test disable while enrollment waits on Touch ID:
        // disable serializes after enrollment and cleans up (S3).
        client
            .call(&Request::BiometricDisable {
                token: token.clone(),
            })
            .unwrap();
        let (entered, release) = mock.pause_next_prompt();
        let sock = paths.socket_file().to_path_buf();
        let tok_en = token.clone();
        let enrolling = thread::spawn(move || {
            let mut c = Client::connect(&sock).unwrap();
            c.call(&Request::BiometricEnable { token: tok_en })
        });
        entered.wait();
        let sock = paths.socket_file().to_path_buf();
        let tok_dis = token.clone();
        let disabling = thread::spawn(move || {
            let mut c = Client::connect(&sock).unwrap();
            c.call(&Request::BiometricDisable { token: tok_dis })
        });
        thread::sleep(Duration::from_millis(20));
        release.wait();
        assert!(enrolling.join().unwrap().is_ok());
        let Reply::Status(status) = disabling.join().unwrap().unwrap() else {
            panic!()
        };
        assert!(!status.biometric_enabled);
        assert!(mock.keys.lock().unwrap().is_empty());
        assert!(!paths.biometric_file().exists());

        // Re-enable, then verify out-of-range TTL is rejected without panicking or installing a session (S12).
        client
            .call(&Request::BiometricEnable {
                token: token.clone(),
            })
            .unwrap();
        client.call(&Request::Lock).unwrap();
        assert!(matches!(
            client.call(&Request::UnlockBiometric {
                ttl_secs: Some(u64::MAX)
            }),
            Err(crate::client::ClientError::Agent(
                AgentError::Invalid { .. }
            ))
        ));
        assert!(matches!(
            client.call(&Request::Unlock {
                password: "pw".into(),
                ttl_secs: Some(u64::MAX),
            }),
            Err(crate::client::ClientError::Agent(
                AgentError::Invalid { .. }
            ))
        ));
        let Reply::Status(status) = client.call(&Request::Status).unwrap() else {
            panic!()
        };
        assert!(!status.unlocked);

        // Fail Keychain deletion once on disable: record stays until retry succeeds (S4).
        mock.fail_delete_next.store(true, Ordering::SeqCst);
        assert!(matches!(
            client.call(&Request::BiometricDisable {
                token: token.clone()
            }),
            Err(crate::client::ClientError::Agent(
                AgentError::Biometric { .. }
            ))
        ));
        assert!(paths.biometric_file().exists());
        assert_eq!(mock.keys.lock().unwrap().len(), 1);

        let Reply::Status(status) = client
            .call(&Request::BiometricDisable {
                token: token.clone(),
            })
            .unwrap()
        else {
            panic!()
        };
        assert!(!status.biometric_enabled);
        assert!(mock.keys.lock().unwrap().is_empty());
        assert!(!paths.biometric_file().exists());

        client.call(&Request::Lock).unwrap();
        assert!(matches!(
            client.call(&Request::UnlockBiometric { ttl_secs: None }),
            Err(crate::client::ClientError::Agent(
                AgentError::Biometric { .. }
            ))
        ));

        client.call(&Request::Shutdown).unwrap();
        server.join().unwrap().unwrap();
        assert!(!paths.admin_token_file().exists());
    }
}
