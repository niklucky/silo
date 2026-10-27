//! Blocking HTTP client for the sync server.

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use silo_core::sync::{
    ChangesReply, DeviceInfo, DevicesReply, ErrorReply, HistoryReply, HistoryRequest, LoginRequest,
    PreloginReply, PushReply, PushRequest, RegisterRequest, ServerInfo, SessionReply,
};

use super::SyncError;

const TIMEOUT: Duration = Duration::from_secs(60);
/// Replies can carry file secrets; the server accepts pushes up to 64 MiB.
const MAX_REPLY_BYTES: u64 = 256 * 1024 * 1024;

pub struct HttpClient {
    base: String,
    token: Option<String>,
    agent: ureq::Agent,
}

impl HttpClient {
    /// `server` is the base URL, e.g. `https://silo.example.com`. Plain HTTP is
    /// allowed for loopback addresses only.
    pub fn new(server: &str) -> Result<Self, SyncError> {
        let base = normalize_server(server)?;
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        Ok(Self {
            base,
            token: None,
            agent,
        })
    }

    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_owned());
        self
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn server_info(&self) -> Result<ServerInfo, SyncError> {
        self.get("/v1/server")
    }

    pub fn prelogin(&self, username: &str) -> Result<PreloginReply, SyncError> {
        self.get(&format!("/v1/prelogin/{username}"))
    }

    pub fn register(&self, request: &RegisterRequest) -> Result<SessionReply, SyncError> {
        self.post("/v1/register", request)
    }

    pub fn login(&self, request: &LoginRequest) -> Result<SessionReply, SyncError> {
        self.post("/v1/login", request)
    }

    pub fn logout(&self) -> Result<(), SyncError> {
        self.send_empty("POST", "/v1/logout")
    }

    pub fn devices(&self) -> Result<Vec<DeviceInfo>, SyncError> {
        self.get::<DevicesReply>("/v1/devices").map(|r| r.devices)
    }

    pub fn revoke_device(&self, id: &str) -> Result<(), SyncError> {
        self.send_empty("DELETE", &format!("/v1/devices/{id}"))
    }

    pub fn changes(&self, since: u64) -> Result<ChangesReply, SyncError> {
        self.get(&format!("/v1/changes?since={since}"))
    }

    pub fn connections(&self) -> Result<Vec<silo_core::sync::ConnectionInfo>, SyncError> {
        self.get::<silo_core::sync::ConnectionsReply>("/v1/connections")
            .map(|r| r.connections)
    }

    pub fn connect(&self, username: &str) -> Result<silo_core::sync::ConnectionInfo, SyncError> {
        let request = self
            .agent
            .put(self.url(&format!("/v1/connections/{username}")))
            .header(
                "Authorization",
                format!("Bearer {}", self.token.as_deref().unwrap_or_default()),
            );
        read(request.send_empty().map_err(network)?)
    }

    pub fn disconnect(&self, username: &str) -> Result<(), SyncError> {
        self.send_empty("DELETE", &format!("/v1/connections/{username}"))
    }

    pub fn push(&self, request: &PushRequest) -> Result<PushReply, SyncError> {
        self.post("/v1/push", request)
    }

    pub fn history(&self, request: &HistoryRequest) -> Result<HistoryReply, SyncError> {
        self.post("/v1/history", request)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, SyncError> {
        let mut request = self.agent.get(self.url(path));
        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        read(request.call().map_err(network)?)
    }

    fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, SyncError> {
        let mut request = self.agent.post(self.url(path));
        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        read(request.send_json(body).map_err(network)?)
    }

    fn send_empty(&self, method: &str, path: &str) -> Result<(), SyncError> {
        let auth = self.token.as_ref().map(|t| format!("Bearer {t}"));
        let response = if method == "DELETE" {
            let mut request = self.agent.delete(self.url(path));
            if let Some(auth) = &auth {
                request = request.header("Authorization", auth);
            }
            request.call()
        } else {
            let mut request = self.agent.post(self.url(path));
            if let Some(auth) = &auth {
                request = request.header("Authorization", auth);
            }
            request.send_empty()
        }
        .map_err(network)?;
        check(response).map(|_| ())
    }
}

fn read<T: DeserializeOwned>(response: ureq::http::Response<ureq::Body>) -> Result<T, SyncError> {
    let mut response = check(response)?;
    response
        .body_mut()
        .with_config()
        .limit(MAX_REPLY_BYTES)
        .read_json()
        .map_err(|err| SyncError::Protocol(format!("unreadable reply: {err}")))
}

/// Turns an error status into [`SyncError::Server`] with the server's message.
fn check(
    mut response: ureq::http::Response<ureq::Body>,
) -> Result<ureq::http::Response<ureq::Body>, SyncError> {
    let status = response.status().as_u16();
    if response.status().is_success() {
        return Ok(response);
    }
    let reply = response.body_mut().read_json::<ErrorReply>().ok();
    Err(SyncError::Server {
        status,
        code: reply.as_ref().map(|r| r.error.code),
        message: reply.map_or_else(|| format!("HTTP {status}"), |r| r.error.message),
    })
}

fn network(err: ureq::Error) -> SyncError {
    SyncError::Network(err.to_string())
}

/// Trims the URL and checks it: HTTPS, or HTTP to this machine, with no
/// credentials, query or fragment.
pub fn normalize_server(server: &str) -> Result<String, SyncError> {
    let trimmed = server.trim().trim_end_matches('/');
    let invalid = |why: &str| SyncError::Config(format!("{trimmed:?}: {why}"));
    let uri: ureq::http::Uri = trimmed
        .parse()
        .map_err(|_| invalid("not a server address"))?;
    let authority = uri
        .authority()
        .filter(|a| !a.host().is_empty())
        .ok_or_else(|| invalid("not a server address"))?;
    if authority.as_str().contains('@') {
        return Err(invalid("must not contain a user name or password"));
    }
    if trimmed.contains(['?', '#']) {
        return Err(invalid("not a server address"));
    }
    match uri.scheme_str() {
        Some("https") => {}
        Some("http") if matches!(authority.host(), "localhost" | "127.0.0.1" | "[::1]") => {}
        Some("http") => return Err(invalid("use https:// (plain http only for localhost)")),
        _ => return Err(invalid("must start with https://")),
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls() {
        assert_eq!(
            normalize_server(" https://silo.example.com/ ").unwrap(),
            "https://silo.example.com"
        );
        assert_eq!(
            normalize_server("http://localhost:8787").unwrap(),
            "http://localhost:8787"
        );
        assert!(normalize_server("http://127.0.0.1:8787").is_ok());
        assert!(normalize_server("http://[::1]:8787").is_ok());
        assert!(normalize_server("http://silo.example.com").is_err());
        assert!(normalize_server("http://localhost.evil.com").is_err());
        assert!(normalize_server("silo.example.com").is_err());
        assert!(normalize_server("https://").is_err());
        assert!(normalize_server("https://x.com/?a=b").is_err());
        assert!(normalize_server("https://x.com/#a").is_err());
        assert!(normalize_server("ftp://x.com").is_err());
        // Assembled here so secret scanners don't take them for credentials.
        for (scheme, userinfo, host) in [
            ("http", "localhost:ignored", "remote.example"),
            ("http", "localhost", "remote.example"),
            ("https", "user:pw", "silo.example.com"),
        ] {
            assert!(normalize_server(&format!("{scheme}://{userinfo}@{host}")).is_err());
        }
        assert_eq!(
            normalize_server("https://silo.example.com/base/").unwrap(),
            "https://silo.example.com/base"
        );
    }
}
