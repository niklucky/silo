//! Matching a stored URL pattern against the URL a browser is visiting.
//!
//! Patterns are what people type when saving a login. Three shapes are accepted:
//!
//! - `dev.example.com` or `dev.example.com:8443`: any scheme, this host (and
//!   port, if given), any path.
//! - `https://dev.example.com/admin`: scheme and port must match too; the path
//!   must start with `/admin` at a segment boundary (`/admin/x` yes, `/adminx` no).
//! - `*.example.com`: the host itself or any subdomain.
//!
//! Query strings and fragments are ignored on both sides. Hosts compare
//! case-insensitively; paths compare exactly.

use url::Url;

/// How specifically a pattern matched. Higher is more specific.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UrlMatch(u32);

impl UrlMatch {
    pub fn score(self) -> u32 {
        self.0
    }
}

/// Returns a match score when `pattern` applies to `target`, or `None`.
pub fn url_match(pattern: &str, target: &Url) -> Option<UrlMatch> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return None;
    }
    let explicit_scheme = pattern.contains("://");
    let parsed = if explicit_scheme {
        Url::parse(pattern).ok()?
    } else {
        Url::parse(&format!("https://{pattern}")).ok()?
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let target_host = target.host_str()?;
    let pattern_host = parsed.host_str()?;

    let mut score = 0;
    if let Some(suffix) = pattern_host.strip_prefix("*.") {
        if suffix.is_empty() {
            return None;
        }
        let is_sub = target_host
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.'));
        if !(is_sub || target_host == suffix) {
            return None;
        }
        score += 1;
    } else {
        if target_host != pattern_host {
            return None;
        }
        score += 2;
    }

    if explicit_scheme {
        if parsed.scheme() != target.scheme()
            || parsed.port_or_known_default() != target.port_or_known_default()
        {
            return None;
        }
        score += 1;
    } else if let Some(port) = parsed.port().or_else(|| explicit_port(pattern)) {
        // `Url` drops a port equal to the scheme default, so look at the raw text too.
        if target.port_or_known_default() != Some(port) {
            return None;
        }
        score += 1;
    }

    let prefix = parsed.path().trim_end_matches('/');
    if !prefix.is_empty() {
        let path = target.path();
        let rest = path.strip_prefix(prefix)?;
        if !(rest.is_empty() || rest.starts_with('/')) {
            return None;
        }
        score += prefix.matches('/').count() as u32;
    }
    Some(UrlMatch(score))
}

/// The port written in a bare `host[:port][/path]` pattern, if any.
fn explicit_port(pattern: &str) -> Option<u16> {
    let authority = pattern.split('/').next()?;
    let host_end = authority.rfind(']').map_or(0, |i| i + 1);
    let (_, port) = authority[host_end..].rsplit_once(':')?;
    port.parse().ok()
}

/// The best score among several patterns, or `None` if none applies.
pub fn best_url_match<'a>(
    patterns: impl IntoIterator<Item = &'a str>,
    target: &Url,
) -> Option<UrlMatch> {
    patterns
        .into_iter()
        .filter_map(|pattern| url_match(pattern, target))
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(pattern: &str, target: &str) -> Option<u32> {
        url_match(pattern, &Url::parse(target).unwrap()).map(UrlMatch::score)
    }

    #[test]
    fn bare_host_matches_any_scheme_port_and_path() {
        assert_eq!(score("dev.example.com", "http://dev.example.com/"), Some(2));
        assert_eq!(
            score("dev.example.com", "https://dev.example.com:8443/x/y"),
            Some(2)
        );
        assert_eq!(score("DEV.example.com", "https://dev.EXAMPLE.com"), Some(2));
        assert_eq!(score("dev.example.com", "https://example.com"), None);
        assert_eq!(score("dev.example.com", "https://xdev.example.com"), None);
    }

    #[test]
    fn explicit_port_must_match() {
        assert_eq!(
            score("dev.example.com:8443", "https://dev.example.com:8443"),
            Some(3)
        );
        assert_eq!(
            score("dev.example.com:8443", "https://dev.example.com"),
            None
        );
        assert_eq!(
            score("dev.example.com:443", "https://dev.example.com"),
            Some(3)
        );
        assert_eq!(score("dev.example.com:443", "http://dev.example.com"), None);
        assert_eq!(score("[::1]:8080", "http://[::1]:8080/"), Some(3));
        assert_eq!(score("[::1]", "http://[::1]:8080/"), Some(2));
    }

    #[test]
    fn explicit_scheme_pins_scheme_and_default_port() {
        assert_eq!(
            score("https://dev.example.com", "https://dev.example.com/"),
            Some(3)
        );
        assert_eq!(
            score("https://dev.example.com", "http://dev.example.com/"),
            None
        );
        assert_eq!(
            score("https://dev.example.com", "https://dev.example.com:8443"),
            None
        );
        assert_eq!(
            score("http://localhost:8099", "http://localhost:8099/private"),
            Some(3)
        );
        assert_eq!(
            score("ftp://dev.example.com", "https://dev.example.com"),
            None
        );
    }

    #[test]
    fn path_prefix_respects_segment_boundaries() {
        let t = "https://h.example.com/admin/users?x=1#top";
        assert_eq!(score("https://h.example.com/admin", t), Some(4));
        assert_eq!(score("https://h.example.com/admin/", t), Some(4));
        assert_eq!(score("https://h.example.com/admin/users", t), Some(5));
        assert_eq!(score("https://h.example.com/adm", t), None);
        assert_eq!(score("https://h.example.com/admin/users/1", t), None);
        assert_eq!(score("h.example.com/admin", "https://h.example.com/"), None);
    }

    #[test]
    fn wildcard_covers_subdomains_and_apex() {
        assert_eq!(score("*.example.com", "https://a.b.example.com"), Some(1));
        assert_eq!(score("*.example.com", "https://example.com"), Some(1));
        assert_eq!(score("*.example.com", "https://notexample.com"), None);
        assert_eq!(score("*.", "https://example.com"), None);
    }

    #[test]
    fn garbage_never_matches() {
        assert_eq!(score("", "https://example.com"), None);
        assert_eq!(score("   ", "https://example.com"), None);
        assert_eq!(score("not a url", "https://example.com"), None);
        assert_eq!(score("https://", "https://example.com"), None);
    }

    #[test]
    fn best_match_prefers_the_most_specific_pattern() {
        let target = Url::parse("https://dev.example.com/admin/x").unwrap();
        let patterns = [
            "*.example.com",
            "dev.example.com",
            "https://dev.example.com/admin",
        ];
        assert_eq!(
            best_url_match(patterns, &target).map(UrlMatch::score),
            Some(4)
        );
        assert_eq!(best_url_match(["other.com"], &target), None);
        assert_eq!(best_url_match([], &target), None);
    }
}
