//! Bridge from the UI to the local agent.
//!
//! The desktop app is a client of the same agent as the CLI and the browser
//! extension: one JSON request in, one JSON response out, over the agent's
//! Unix socket. The agent holds the unlocked session. The desktop also creates
//! the first local account. If no agent is running, it starts one with the bundled
//! `silo` binary, using the same agent command as the standalone CLI.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use silo_agent::client::{self, Client, ClientError};
use silo_agent::protocol::{AgentError, Request, Response};
use silo_agent::{Paths, Store, initialize_account};

#[derive(Default)]
pub struct Agent {
    /// From the environment (SILO_HOME, SILO_AGENT_SOCKET) unless set.
    paths: Option<Paths>,
    client: Mutex<Option<Client>>,
}

impl Agent {
    #[cfg(test)]
    fn with_paths(paths: Paths) -> Self {
        Self {
            paths: Some(paths),
            client: Mutex::default(),
        }
    }

    /// Local setup belongs to the desktop, outside the shared socket protocol.
    /// A running agent only needs to support the existing unlock request.
    pub fn create_vault(&self, password: &str) -> Result<(), String> {
        let paths = self.paths().map_err(|err| err.to_string())?;
        let store = Store::open(paths).map_err(|err| err.to_string())?;
        initialize_account(&store, password)
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    fn paths(&self) -> io::Result<Paths> {
        match &self.paths {
            Some(paths) => Ok(paths.clone()),
            None => Paths::from_env().map_err(io::Error::other),
        }
    }

    /// Forwards one request, given as agent-protocol JSON, and returns the
    /// response as JSON. Agent errors come back as `{"err":…}`, like over the
    /// socket; transport failures too, as an `internal` error.
    pub fn call_json(&self, request: &str) -> String {
        let response = match serde_json::from_str::<Request>(request) {
            Ok(request) => self.call(&request),
            Err(err) => Response::Err(AgentError::Invalid {
                message: err.to_string(),
            }),
        };
        serde_json::to_string(&response).unwrap_or_else(|err| {
            format!(
                r#"{{"err":{{"code":"internal","message":{:?}}}}}"#,
                err.to_string()
            )
        })
    }

    fn call(&self, request: &Request) -> Response {
        // The app must not stop the agent the CLI and browsers share.
        if matches!(request, Request::Shutdown) {
            return Response::Err(AgentError::Invalid {
                message: "the desktop app does not stop the agent".to_owned(),
            });
        }
        let mut slot = self.client.lock().unwrap_or_else(|e| e.into_inner());
        let unreachable = |err: ClientError| {
            Response::Err(AgentError::Internal {
                message: format!("cannot reach the agent: {err}"),
            })
        };
        match self.try_call(&mut slot, request) {
            Ok(response) => response,
            Err(err) => {
                // The connection is dead either way (agent restarted, `silo agent stop`).
                *slot = None;
                // Send again only what cannot be applied twice: a request the
                // agent never received, or one that changes nothing.
                if matches!(err, ClientError::Unsent(_)) || is_read_only(request) {
                    self.try_call(&mut slot, request)
                        .unwrap_or_else(unreachable)
                } else {
                    Response::Err(AgentError::Internal {
                        message: format!(
                            "the agent stopped answering ({err}); the change may or may not have been saved, so check before trying again"
                        ),
                    })
                }
            }
        }
    }

    /// `Err` only for transport failures, where reconnecting might help.
    fn try_call(
        &self,
        slot: &mut Option<Client>,
        request: &Request,
    ) -> Result<Response, ClientError> {
        if slot.is_none() {
            *slot = Some(connect(&self.paths()?)?);
        }
        let client = slot.as_mut().expect("set above");
        match client.call(request) {
            Ok(reply) => Ok(Response::Ok(reply)),
            Err(ClientError::Agent(err)) => Ok(Response::Err(err)),
            Err(err) => Err(err),
        }
    }
}

/// Requests that change nothing in the vault, so sending one twice is harmless.
fn is_read_only(request: &Request) -> bool {
    matches!(
        request,
        Request::Status
            | Request::Lock
            | Request::List(_)
            | Request::Get { .. }
            | Request::History { .. }
            | Request::Match { .. }
            | Request::Site { .. }
            | Request::SyncStatus
            | Request::SyncDevices
    )
}

fn connect(paths: &Paths) -> Result<Client, ClientError> {
    client::connect_or_spawn(paths, || {
        // On first launch the vault directory must exist before opening the log.
        Store::open(paths.clone()).map_err(io::Error::other)?;
        client::spawn_detached(&silo_binary()?, &["agent", "run"], paths)
    })
}

/// Tauri places the CLI beside the desktop executable. Development builds
/// can use an installed CLI, including common locations outside Finder's PATH.
fn silo_binary() -> io::Result<PathBuf> {
    if let Some(bin) = std::env::var_os("SILO_BIN").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(bin));
    }
    if let Ok(exe) = std::env::current_exe() {
        let bundled = exe.with_file_name("silo");
        if is_executable(&bundled) {
            return Ok(bundled);
        }
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut candidates: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("silo"))
                .collect()
        })
        .unwrap_or_default();
    if let Some(home) = &home {
        candidates.push(home.join(".cargo/bin/silo"));
        candidates.push(home.join(".local/bin/silo"));
    }
    candidates.push(PathBuf::from("/opt/homebrew/bin/silo"));
    candidates.push(PathBuf::from("/usr/local/bin/silo"));
    candidates
        .into_iter()
        .find(|p| is_executable(p))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "the silo CLI was not found; install it with `cargo install --path crates/cli` or set SILO_BIN",
            )
        })
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use serde_json::{Value, json};
    use silo_agent::Reply;
    use silo_agent::{Store, server};
    use silo_core::AccountRecord;
    use silo_core::crypto::KdfParams;
    use std::{thread, time::Duration};

    #[test]
    fn creates_a_vault_on_the_existing_agent_protocol() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixStream;

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let store = Store::open(paths.clone()).unwrap();
        let worker = thread::spawn(move || {
            server::run(server::Config {
                store,
                default_ttl: server::DEFAULT_TTL,
                sync_interval: None,
            })
        });
        let mut client = client::connect_or_spawn(&paths, || Ok(())).unwrap();
        assert!(matches!(
            client.call(&Request::Status).unwrap(),
            Reply::Status(status) if !status.has_account
        ));
        let setup = Agent::with_paths(paths.clone());
        let mut old_bridge = UnixStream::connect(paths.socket_file()).unwrap();
        old_bridge
            .write_all(b"{\"method\":\"init\",\"params\":{\"password\":\"\"}}\n")
            .unwrap();
        let mut response = String::new();
        BufReader::new(old_bridge).read_line(&mut response).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&response).unwrap()["err"]["code"],
            "invalid"
        );
        assert!(setup.create_vault("").is_err());
        assert!(!paths.account_file().exists());

        let example = "example master phrase";
        setup.create_vault(example).unwrap();
        let original = std::fs::read(paths.account_file()).unwrap();
        assert!(setup.create_vault(&format!("{example} again")).is_err());
        assert_eq!(std::fs::read(paths.account_file()).unwrap(), original);
        assert!(matches!(
            client.call(&Request::Unlock { password: example.into(), ttl_secs: None }).unwrap(),
            Reply::Unlocked(status) if status.has_account && status.unlocked
        ));

        client.call(&Request::Shutdown).unwrap();
        worker.join().unwrap().unwrap();
    }

    /// Requests shaped exactly as `@silo/ui`'s agent client sends them.
    #[test]
    fn forwards_ui_requests_to_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let store = Store::open(paths.clone()).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let kdf = KdfParams::new(&mut rng, 256, 1, 1);
        let (record, _) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();
        store.write_account(&record).unwrap();
        thread::spawn(move || {
            server::run(server::Config {
                store,
                default_ttl: server::DEFAULT_TTL,
                sync_interval: None,
            })
        });
        for _ in 0..200 {
            if Client::connect(paths.socket_file()).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        let agent = Agent::with_paths(paths);
        let call = |request: Value| -> Value {
            serde_json::from_str(&agent.call_json(&request.to_string())).unwrap()
        };

        assert_eq!(
            call(json!({"method": "list", "params": {}}))["err"]["code"],
            "locked"
        );
        assert_eq!(
            call(json!({"method": "unlock", "params": {"password": "nope"}}))["err"]["code"],
            "wrong_password"
        );
        assert_eq!(
            call(json!({"method": "unlock", "params": {"password": "pw"}}))["ok"]["unlocked"]["unlocked"],
            true
        );

        let added = call(json!({"method": "add", "params": {
            "title": "dev", "folder": "projects/api", "tags": ["env"], "urls": [],
            "body": {"env_set": {"vars": [{"key": "PORT", "value": "8080"}]}}
        }}));
        let id = added["ok"]["added"]["id"].as_str().unwrap().to_owned();

        let list = call(json!({"method": "list", "params": {}}));
        assert_eq!(list["ok"]["list"][0]["meta"]["folder"], "projects/api");

        let updated = call(json!({"method": "update", "params": {
            "selector": id, "revision": 1, "title": "dev", "folder": "projects/api", "tags": ["env"], "urls": [],
            "body": {"env_set": {"vars": [{"key": "PORT", "value": "9090"}]}}
        }}));
        assert_eq!(updated["ok"]["updated"]["revision"], 2);
        let stale = call(
            json!({"method": "update", "params": {"selector": id, "revision": 1, "title": "x"}}),
        );
        assert_eq!(stale["err"]["code"], "stale");

        let got = call(json!({"method": "get", "params": {"selector": id}}));
        assert_eq!(
            got["ok"]["secret"]["body"]["env_set"]["vars"][0]["value"],
            "9090"
        );
        let history = call(json!({"method": "history", "params": {"selector": id}}));
        assert_eq!(history["ok"]["history"][0]["revision"], 1);
        assert_eq!(
            call(json!({"method": "sync_status"}))["ok"]["sync_status"],
            Value::Null
        );

        assert_eq!(
            call(json!({"method": "shutdown"}))["err"]["code"],
            "invalid"
        );
        assert_eq!(
            call(json!({"method": "nonsense"}))["err"]["code"],
            "invalid"
        );
        assert_eq!(
            call(json!({"method": "remove", "params": {"selector": id}}))["ok"]["removed"]["id"],
            id.as_str()
        );
        assert_eq!(call(json!({"method": "lock"}))["ok"], "locked");
    }

    /// The two ways a kept connection dies. Closed before the request: the
    /// request is sent again on a new connection. Closed after reading it
    /// without answering: a change is not sent again, since it may have landed.
    #[test]
    fn resends_only_what_cannot_apply_twice() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let store = Store::open(paths.clone()).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(4);
        let kdf = KdfParams::new(&mut rng, 256, 1, 1);
        let (record, _) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();
        store.write_account(&record).unwrap();
        thread::spawn(move || {
            server::run(server::Config {
                store,
                default_ttl: server::DEFAULT_TTL,
                sync_interval: None,
            })
        });
        for _ in 0..200 {
            if Client::connect(paths.socket_file()).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let agent = Agent::with_paths(paths);
        let call = |request: Value| -> Value {
            serde_json::from_str(&agent.call_json(&request.to_string())).unwrap()
        };
        assert_eq!(
            call(json!({"method": "unlock", "params": {"password": "pw"}}))["ok"]["unlocked"]["unlocked"],
            true
        );
        let note =
            json!({"method": "add", "params": {"title": "n", "body": {"note": {"text": "x"}}}});
        let count = |call: &dyn Fn(Value) -> Value| {
            call(json!({"method": "list", "params": {}}))["ok"]["list"]
                .as_array()
                .unwrap()
                .len()
        };

        // A connection to a peer that is already gone.
        let dead = dir.path().join("dead.sock");
        let listener = UnixListener::bind(&dead).unwrap();
        let client = Client::connect(&dead).unwrap();
        drop(listener.accept().unwrap());
        *agent.client.lock().unwrap() = Some(client);
        assert!(call(note.clone())["ok"]["added"].is_object());
        assert_eq!(count(&call), 1);

        // A peer that takes the request and hangs up without answering.
        let mute = dir.path().join("mute.sock");
        let listener = UnixListener::bind(&mute).unwrap();
        let client = Client::connect(&mute).unwrap();
        let peer = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            BufReader::new(stream)
                .read_line(&mut String::new())
                .unwrap();
        });
        *agent.client.lock().unwrap() = Some(client);
        let reply = call(note);
        peer.join().unwrap();
        assert_eq!(reply["err"]["code"], "internal", "{reply}");
        assert!(
            reply["err"]["message"]
                .as_str()
                .unwrap()
                .contains("may or may not")
        );
        assert_eq!(count(&call), 1, "the change was not sent again");
    }
}
