use std::path::{Path, PathBuf};

/// Where the agent keeps its files. Resolved once from the environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    home: PathBuf,
    socket: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum PathsError {
    #[error("neither SILO_HOME nor HOME is set")]
    NoHome,
}

impl Paths {
    /// Overrides the data directory. Default: `$HOME/.secret`.
    pub const HOME_ENV: &'static str = "SILO_HOME";
    /// Overrides the socket path. Default: `<home>/agent.sock`.
    pub const SOCKET_ENV: &'static str = "SILO_AGENT_SOCKET";

    pub fn from_env() -> Result<Self, PathsError> {
        let home = match std::env::var_os(Self::HOME_ENV).filter(|v| !v.is_empty()) {
            Some(home) => PathBuf::from(home),
            None => {
                let user_home = std::env::var_os("HOME")
                    .filter(|v| !v.is_empty())
                    .ok_or(PathsError::NoHome)?;
                PathBuf::from(user_home).join(".silo")
            }
        };
        let mut paths = Self::new(home);
        if let Some(socket) = std::env::var_os(Self::SOCKET_ENV).filter(|v| !v.is_empty()) {
            paths.socket = PathBuf::from(socket);
        }
        Ok(paths)
    }

    pub fn new(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let socket = home.join("agent.sock");
        Self { home, socket }
    }

    pub fn with_socket(mut self, socket: impl Into<PathBuf>) -> Self {
        self.socket = socket.into();
        self
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn account_file(&self) -> PathBuf {
        self.home.join("account.json")
    }

    pub fn vault_dir(&self) -> PathBuf {
        self.home.join("vault")
    }

    pub fn socket_file(&self) -> &Path {
        &self.socket
    }

    pub fn log_file(&self) -> PathBuf {
        self.home.join("agent.log")
    }
}
