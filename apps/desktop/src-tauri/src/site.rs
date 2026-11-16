//! Plain GETs to the websites saved in logins, for their favicons. The webview
//! cannot read other origins itself (CORS), so the UI asks this host instead.
//! No cookies, credentials or referrer are sent, and bodies are capped.

use std::time::Duration;

use base64::Engine;
use serde::Serialize;
use specta::Type;
use ureq::ResponseExt;

const TIMEOUT: Duration = Duration::from_secs(6);
/// The largest body the UI may ask for; a home page is read up to 512 KiB.
const MAX_BODY: u32 = 512 * 1024;

#[derive(Debug, Serialize, Type, PartialEq)]
pub struct SiteResponse {
    /// Where the request ended up after redirects, for resolving relative links.
    pub url: String,
    pub content_type: String,
    /// Base64.
    pub body: String,
}

/// `url`'s body when it answers 2xx within `limit` bytes; `None` otherwise.
/// Only `http` and `https` URLs without credentials are fetched.
pub fn get(url: &str, limit: u32) -> Option<SiteResponse> {
    let uri: ureq::http::Uri = url.parse().ok()?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.authority()?.as_str().contains('@')
    {
        return None;
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .max_redirects(5)
        .build()
        .into();
    let mut response = agent.get(uri).call().ok()?;
    let url = response.get_uri().to_string();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = response
        .body_mut()
        .with_config()
        .limit(u64::from(limit.min(MAX_BODY)))
        .read_to_vec()
        .ok()?;
    Some(SiteResponse {
        url,
        content_type,
        body: base64::engine::general_purpose::STANDARD.encode(body),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    /// Serves `responses` in order, one per connection, on a local port.
    fn serve(responses: Vec<String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap() > 2 {
                    line.clear();
                }
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        format!("http://{addr}")
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn follows_redirects_and_reports_the_final_url() {
        let base = serve(vec![
            "HTTP/1.1 302 Found\r\nLocation: /home\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
            ok("<html></html>"),
        ]);
        let page = get(&format!("{base}/"), 1024).unwrap();
        assert_eq!(page.url, format!("{base}/home"));
        assert_eq!(page.content_type, "text/html");
        assert_eq!(page.body, "PGh0bWw+PC9odG1sPg==");
    }

    #[test]
    fn refuses_errors_oversized_bodies_and_other_schemes() {
        let base = serve(vec![
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
            ok(&"x".repeat(100)),
        ]);
        assert_eq!(get(&format!("{base}/missing"), 1024), None);
        assert_eq!(get(&format!("{base}/big"), 10), None);
        assert_eq!(get("file:///etc/passwd", 1024), None);
        assert_eq!(get("http://user:pw@127.0.0.1:1/", 1024), None);
    }
}
