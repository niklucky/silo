//! `silo-native-host`: the browser's bridge to the agent.
//!
//! A browser starts this binary on behalf of the Silo extension (native
//! messaging) and talks to it over stdin/stdout: a 4-byte native-endian length
//! followed by one JSON message, in both directions. Each message in is one
//! agent `Request`; each message out is one `Response`. The process exits when
//! the browser closes stdin.
//!
//! Only the extension named in the manifest written by `silo browser install`
//! can start it. The bridge forwards requests to the agent socket, starting the
//! agent if needed, and refuses the methods a web-facing client never needs.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use silo_agent::protocol::{AgentError, Request, Response};
use silo_agent::{Client, ClientError, Paths, client};
use zeroize::Zeroize;

/// Requests are tiny; anything larger is a bug or an attack.
const MAX_REQUEST: usize = 4 * 1024 * 1024;
/// Browsers drop host messages above 1 MiB, so fail loudly instead.
const MAX_REPLY: usize = 1024 * 1024;

fn main() -> ExitCode {
    let paths = match Paths::from_env() {
        Ok(paths) => paths,
        Err(err) => {
            eprintln!("silo-native-host: {err}");
            return ExitCode::FAILURE;
        }
    };
    let mut bridge = Bridge { paths, agent: None };
    let stdin = io::stdin().lock();
    let stdout = io::stdout().lock();
    match bridge.serve(stdin, stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("silo-native-host: {err}");
            ExitCode::FAILURE
        }
    }
}

struct Bridge {
    paths: Paths,
    agent: Option<Client>,
}

impl Bridge {
    /// Serves framed requests until `input` ends.
    fn serve(&mut self, mut input: impl Read, mut output: impl Write) -> io::Result<()> {
        while let Some(mut message) = read_message(&mut input)? {
            let response = match serde_json::from_slice::<Request>(&message) {
                Ok(request) => self.handle(&request),
                Err(err) => Response::Err(AgentError::Invalid {
                    message: err.to_string(),
                }),
            };
            message.zeroize();
            let mut encoded = serde_json::to_vec(&response).unwrap_or_else(|err| {
                serde_json::to_vec(&Response::Err(AgentError::Internal {
                    message: err.to_string(),
                }))
                .expect("static error encodes")
            });
            if encoded.len() > MAX_REPLY {
                encoded.zeroize();
                encoded = serde_json::to_vec(&Response::Err(AgentError::Internal {
                    message: format!("reply exceeds the {MAX_REPLY} byte native messaging limit"),
                }))
                .expect("static error encodes");
            }
            let written = write_message(&mut output, &encoded);
            encoded.zeroize();
            written?;
        }
        Ok(())
    }

    fn handle(&mut self, request: &Request) -> Response {
        // Browsers can manage secrets, but cannot read old revisions or
        // change where the vault syncs.
        if matches!(
            request,
            Request::Shutdown
                | Request::History { .. }
                | Request::SyncRegister { .. }
                | Request::SyncLogin { .. }
                | Request::SyncLogout
                | Request::SyncRevokeDevice { .. }
        ) {
            return Response::Err(AgentError::Invalid {
                message: "this method is not available through the browser".to_owned(),
            });
        }
        match self.call(request) {
            Ok(response) => response,
            Err(_) => {
                // The agent went away (restart, crash, `silo agent stop`): reconnect once.
                self.agent = None;
                self.call(request).unwrap_or_else(|err| {
                    Response::Err(AgentError::Internal {
                        message: format!("cannot reach the agent: {err}"),
                    })
                })
            }
        }
    }

    /// `Err` only for transport failures, where reconnecting might help.
    fn call(&mut self, request: &Request) -> Result<Response, ClientError> {
        let agent = self.connect()?;
        match agent.call(request) {
            Ok(reply) => Ok(Response::Ok(reply)),
            Err(ClientError::Agent(err)) => Ok(Response::Err(err)),
            Err(err) => Err(err),
        }
    }

    fn connect(&mut self) -> Result<&mut Client, ClientError> {
        if self.agent.is_none() {
            let paths = self.paths.clone();
            let client = client::connect_or_spawn(&paths, || {
                client::spawn_detached(&silo_binary()?, &["agent", "run"], &paths)
            })?;
            self.agent = Some(client);
        }
        Ok(self.agent.as_mut().expect("set above"))
    }
}

/// The `silo` binary installed next to this one, used to start the agent.
fn silo_binary() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| io::Error::other("native host has no parent directory"))?;
    let silo = dir.join("silo");
    if !silo.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{} is missing; reinstall with `cargo install --path crates/cli`",
                silo.display()
            ),
        ));
    }
    Ok(silo)
}

/// One framed message, or `None` once the browser has closed the stream.
fn read_message(input: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    match input.read_exact(&mut header) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = u32::from_ne_bytes(header) as usize;
    if len > MAX_REQUEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("request of {len} bytes exceeds the {MAX_REQUEST} byte limit"),
        ));
    }
    let mut body = vec![0u8; len];
    input.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_message(output: &mut impl Write, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "reply too large"))?;
    output.write_all(&len.to_ne_bytes())?;
    output.write_all(body)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::thread;
    use std::time::Duration;

    use rand::SeedableRng;
    use silo_agent::protocol::Reply;
    use silo_agent::{Store, server};
    use silo_core::AccountRecord;
    use silo_core::crypto::KdfParams;

    use super::*;

    fn frame(request: &Request) -> Vec<u8> {
        let body = serde_json::to_vec(request).unwrap();
        let mut out = (body.len() as u32).to_ne_bytes().to_vec();
        out.extend(body);
        out
    }

    fn unframe(mut bytes: &[u8]) -> Vec<Response> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let len = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
            out.push(serde_json::from_slice(&bytes[4..4 + len]).unwrap());
            bytes = &bytes[4 + len..];
        }
        out
    }

    #[test]
    fn bridges_frames_to_the_agent_and_filters_methods() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path());
        let store = Store::open(paths.clone()).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let kdf = KdfParams::new(&mut rng, 256, 1, 1);
        let (record, _) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();
        store.write_account(&record).unwrap();
        let agent = thread::spawn(move || {
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

        let mut input = Vec::new();
        for request in [
            Request::Status,
            Request::Shutdown,
            Request::Unlock {
                password: "pw".into(),
                ttl_secs: None,
            },
            Request::Match {
                url: "https://nothing.test/".into(),
                site: false,
            },
        ] {
            input.extend(frame(&request));
        }
        input.extend(b"{}"); // a truncated header ends the stream quietly
        let mut output = Vec::new();
        let mut bridge = Bridge {
            paths: paths.clone(),
            agent: None,
        };
        bridge.serve(Cursor::new(input), &mut output).unwrap();

        let responses = unframe(&output);
        assert_eq!(responses.len(), 4, "{responses:?}");
        assert!(matches!(responses[0], Response::Ok(Reply::Status(_))));
        assert!(matches!(
            responses[1],
            Response::Err(AgentError::Invalid { .. })
        ));
        assert!(matches!(responses[2], Response::Ok(Reply::Unlocked(_))));
        assert!(matches!(&responses[3], Response::Ok(Reply::Matches(m)) if m.is_empty()));

        let add: Request = serde_json::from_value(serde_json::json!({
            "method": "add",
            "params": { "title": "popup-delete", "body": { "note": { "text": "test" } } }
        }))
        .unwrap();
        let Response::Ok(Reply::Added(added)) = bridge.handle(&add) else {
            panic!("browser can add a secret");
        };
        let selector = added.id.to_string();
        assert!(matches!(
            bridge.handle(&Request::Remove { selector: selector.clone() }),
            Response::Ok(Reply::Removed(removed)) if removed.id == added.id
        ));
        assert!(matches!(
            bridge.handle(&Request::Get {
                selector: selector.clone()
            }),
            Response::Err(AgentError::NotFound { .. })
        ));
        assert!(matches!(
            bridge.handle(&Request::History { selector }),
            Response::Err(AgentError::Invalid { .. })
        ));

        Client::connect(paths.socket_file())
            .unwrap()
            .call(&Request::Shutdown)
            .unwrap();
        agent.join().unwrap().unwrap();
    }

    #[test]
    fn oversized_requests_are_rejected() {
        let mut input = Vec::new();
        input.extend((MAX_REQUEST as u32 + 1).to_ne_bytes());
        let err = read_message(&mut Cursor::new(input)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            read_message(&mut Cursor::new(Vec::new()))
                .unwrap()
                .is_none()
        );
    }
}
