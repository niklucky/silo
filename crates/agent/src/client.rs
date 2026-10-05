//! Synchronous client for the agent socket, plus helpers to start an agent.

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use zeroize::Zeroize;

use crate::paths::Paths;
use crate::protocol::{AgentError, Reply, Request, Response};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("malformed message from agent: {0}")]
    Protocol(#[from] serde_json::Error),
    #[error("agent closed the connection")]
    Disconnected,
    #[error("agent did not start within {0:?}")]
    SpawnTimeout(Duration),
    #[error(transparent)]
    Agent(#[from] AgentError),
}

pub struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Client {
    pub fn connect(socket: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(socket)?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Self {
            reader,
            writer: stream,
        })
    }

    /// Sends one request and waits for its reply.
    pub fn call(&mut self, request: &Request) -> Result<Reply, ClientError> {
        let mut line = serde_json::to_vec(request)?;
        line.push(b'\n');
        let sent = self
            .writer
            .write_all(&line)
            .and_then(|()| self.writer.flush());
        line.zeroize();
        sent?;

        let mut buf = String::new();
        if self.reader.read_line(&mut buf)? == 0 {
            return Err(ClientError::Disconnected);
        }
        let response: Response = serde_json::from_str(buf.trim_end())?;
        Result::from(response).map_err(ClientError::Agent)
    }
}

/// True when the error means "no agent is listening" rather than a real failure.
pub fn is_not_running(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
}

/// Connects to a running agent, or starts one with `spawn` and waits for it.
pub fn connect_or_spawn(
    paths: &Paths,
    spawn: impl FnOnce() -> io::Result<()>,
) -> Result<Client, ClientError> {
    match Client::connect(paths.socket_file()) {
        Ok(client) => return Ok(client),
        Err(err) if is_not_running(&err) => {}
        Err(err) => return Err(err.into()),
    }
    if paths.socket_file().exists() {
        let _ = fs::remove_file(paths.socket_file());
    }
    spawn()?;

    let timeout = Duration::from_secs(5);
    let step = Duration::from_millis(50);
    let mut waited = Duration::ZERO;
    while waited < timeout {
        thread::sleep(step);
        waited += step;
        match Client::connect(paths.socket_file()) {
            Ok(client) => return Ok(client),
            Err(err) if is_not_running(&err) => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Err(ClientError::SpawnTimeout(timeout))
}

/// Starts `program args…` in its own session with stdio sent to the agent log,
/// so it outlives the terminal that started it.
pub fn spawn_detached(program: &Path, args: &[&str], paths: &Paths) -> io::Result<()> {
    let log = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(paths.log_file())?;
    fs::set_permissions(
        paths.log_file(),
        <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env(Paths::HOME_ENV, paths.home())
        .env(Paths::SOCKET_ENV, paths.socket_file())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    // SAFETY: setsid() is async-signal-safe and touches no memory shared with the parent.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    command.spawn()?;
    Ok(())
}
