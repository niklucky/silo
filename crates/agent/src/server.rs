//! The agent process: accepts connections on a Unix socket, one thread each,
//! and serves [`Request`]s against a shared, lockable [`Session`].

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use crate::protocol::{AgentError, Reply, Request, Response, StatusInfo};
use crate::session::Session;
use crate::store::Store;

/// How long a vault stays unlocked unless the client asks otherwise.
pub const DEFAULT_TTL: Duration = Duration::from_secs(12 * 60 * 60);
const EXPIRY_CHECK_INTERVAL: Duration = Duration::from_secs(15);

pub struct Config {
    pub store: Store,
    pub default_ttl: Duration,
}

struct State {
    store: Store,
    session: Option<Session>,
    expires_at: Option<Instant>,
    default_ttl: Duration,
}

struct Shared {
    state: Mutex<State>,
    shutdown: AtomicBool,
    socket: PathBuf,
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

    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            store: config.store,
            session: None,
            expires_at: None,
            default_ttl: config.default_ttl,
        }),
        shutdown: AtomicBool::new(false),
        socket: socket.clone(),
    });

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
        }
        Request::Remove { selector } => {
            let State { store, session, .. } = &mut *state;
            session
                .as_mut()
                .ok_or(AgentError::Locked)
                .and_then(|s| s.remove(store, &selector))
                .map(Reply::Removed)
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
    };
    result.into()
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

    fn session(&mut self) -> Result<&mut Session, AgentError> {
        self.session.as_mut().ok_or(AgentError::Locked)
    }

    fn status(&self) -> StatusInfo {
        StatusInfo {
            agent_version: crate::VERSION.to_owned(),
            core_version: secret_core::version().to_owned(),
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
    use secret_core::AccountRecord;
    use secret_core::crypto::KdfParams;
    use secret_core::vault::{FolderPath, Note, SecretBody};

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
