//! Bridge from the UI to the local agent.
//!
//! The desktop app is a client of the same agent as the CLI and the browser
//! extension: one JSON request in, one JSON response out, over the agent's
//! Unix socket. Keys and plaintext stay in the agent process; this crate only
//! forwards lines. If no agent is running, it starts one with the installed
//! `silo` binary, as `silo unlock` does.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use silo_agent::Paths;
use silo_agent::client::{self, Client, ClientError};
use silo_agent::protocol::{AgentError, Request, Response};

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
        match self.try_call(&mut slot, request) {
            Ok(response) => response,
            Err(_) => {
                // The agent went away (restart, `silo agent stop`): reconnect once.
                *slot = None;
                self.try_call(&mut slot, request).unwrap_or_else(|err| {
                    Response::Err(AgentError::Internal {
                        message: format!("cannot reach the agent: {err}"),
                    })
                })
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
            let paths = match &self.paths {
                Some(paths) => paths.clone(),
                None => Paths::from_env().map_err(|e| io::Error::other(e.to_string()))?,
            };
            *slot = Some(connect(&paths)?);
        }
        let client = slot.as_mut().expect("set above");
        match client.call(request) {
            Ok(reply) => Ok(Response::Ok(reply)),
            Err(ClientError::Agent(err)) => Ok(Response::Err(err)),
            Err(err) => Err(err),
        }
    }
}

fn connect(paths: &Paths) -> Result<Client, ClientError> {
    client::connect_or_spawn(paths, || {
        client::spawn_detached(&silo_binary()?, &["agent", "run"], paths)
    })
}

/// The `silo` CLI, which runs the agent. Apps started from Finder get a
/// minimal PATH, so the usual install locations are tried as well.
fn silo_binary() -> io::Result<PathBuf> {
    if let Some(bin) = std::env::var_os("SILO_BIN").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(bin));
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
    use silo_agent::{Store, server};
    use silo_core::AccountRecord;
    use silo_core::crypto::KdfParams;
    use std::{thread, time::Duration};

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
}
