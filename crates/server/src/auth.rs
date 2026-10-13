//! Device tokens, login backoff and the [`Auth`] extractor.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use silo_core::crypto::{CryptoRng, PublicKey, SigningPublicKey};
use silo_core::sync::ErrorCode;

use crate::AppState;
use crate::error::{ApiError, ApiResult};

const TOKEN_PREFIX: &str = "silo_";

/// An account as the server knows it: who it is and which keys it signs and
/// receives grants with.
#[derive(Clone, Debug)]
pub struct Account {
    pub id: i64,
    pub username: String,
    pub public_key: PublicKey,
    pub signing_key: SigningPublicKey,
}

impl Account {
    pub const COLUMNS: &'static str = "a.id, a.username, a.public_key, a.signing_key";

    pub fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            username: row.get(1)?,
            public_key: PublicKey::from_bytes(row.get(2)?),
            signing_key: SigningPublicKey::from_bytes(row.get(3)?),
        })
    }
}

/// The account and device behind a request's bearer token.
#[derive(Clone, Debug)]
pub struct Auth {
    pub account: Account,
    pub device_id: String,
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(ApiError::unauthorized)?
            .trim()
            .to_owned();
        let now = crate::unix_now();
        state
            .db
            .run(move |conn| authenticate(conn, &token, now))
            .await
    }
}

fn authenticate(conn: &Connection, token: &str, now: u64) -> ApiResult<Auth> {
    let hash = sha256(token.as_bytes());
    let found = conn
        .query_row(
            &format!(
                "SELECT {}, d.id FROM devices d JOIN accounts a ON a.id = d.account_id
                 WHERE d.token_hash = ?1",
                Account::COLUMNS
            ),
            [&hash[..]],
            |row| Ok((Account::from_row(row)?, row.get::<_, String>(4)?)),
        )
        .optional()?;
    let (account, device_id) = found.ok_or_else(ApiError::unauthorized)?;
    conn.execute(
        "UPDATE devices SET last_seen_at = ?1 WHERE id = ?2",
        params![now, device_id],
    )?;
    Ok(Auth { account, device_id })
}

/// A fresh device token and the hash the server keeps of it.
pub fn new_token(rng: &mut impl CryptoRng) -> (String, [u8; 32]) {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    let hash = sha256(token.as_bytes());
    (token, hash)
}

pub fn new_device_id(rng: &mut impl CryptoRng) -> String {
    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Compares without stopping at the first difference.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Slows down password guessing per username: after a few failures, each
/// further attempt has to wait twice as long as the last, up to a limit.
///
/// Kept in memory and bounded, since anyone can fail a login for any name:
/// an entry is forgotten an hour after its last failure, and when the table
/// is full the entry with the fewest failures goes first, so a flood of
/// one-off names cannot push out a name someone is actually guessing at.
/// A restart forgets everything. Guessing stays expensive regardless: every
/// guess costs the guesser an Argon2 run for that account's salt.
pub struct LoginLimiter {
    failures: Mutex<HashMap<String, (u32, Instant)>>,
    capacity: usize,
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::with_capacity(Self::CAPACITY)
    }
}

impl LoginLimiter {
    const FREE_ATTEMPTS: u32 = 5;
    const MAX_WAIT: Duration = Duration::from_secs(15 * 60);
    const FORGET_AFTER: Duration = Duration::from_secs(60 * 60);
    const CAPACITY: usize = 10_000;

    fn with_capacity(capacity: usize) -> Self {
        Self {
            failures: Mutex::default(),
            capacity,
        }
    }

    pub fn check(&self, username: &str) -> ApiResult<()> {
        let failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(&(count, last)) = failures.get(username)
            && count >= Self::FREE_ATTEMPTS
        {
            let wait = Self::wait_after(count);
            let elapsed = last.elapsed();
            if elapsed < wait {
                let secs = (wait - elapsed).as_secs().max(1);
                return Err(ApiError::new(
                    ErrorCode::RateLimited,
                    format!("too many failed logins; try again in {secs} s"),
                ));
            }
        }
        Ok(())
    }

    pub fn failed(&self, username: &str) {
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        if !failures.contains_key(username) && failures.len() >= self.capacity {
            failures.retain(|_, (_, last)| last.elapsed() < Self::FORGET_AFTER);
            if failures.len() >= self.capacity
                && let Some(evict) = failures
                    .iter()
                    .min_by_key(|(_, (count, last))| (*count, *last))
                    .map(|(name, _)| name.clone())
            {
                failures.remove(&evict);
            }
        }
        let now = Instant::now();
        let entry = failures.entry(username.to_owned()).or_insert((0, now));
        if now.duration_since(entry.1) >= Self::FORGET_AFTER {
            entry.0 = 0;
        }
        entry.0 = entry.0.saturating_add(1);
        entry.1 = now;
    }

    pub fn succeeded(&self, username: &str) {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(username);
    }

    fn wait_after(count: u32) -> Duration {
        let doublings = count.saturating_sub(Self::FREE_ATTEMPTS).min(16);
        (Duration::from_secs(1) * 2u32.pow(doublings)).min(Self::MAX_WAIT)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_prefixed_and_hashed() {
        let mut rng = rand::rng();
        let (token, hash) = new_token(&mut rng);
        assert!(token.starts_with("silo_") && token.len() > 40);
        assert_eq!(hash, sha256(token.as_bytes()));
        assert_ne!(new_token(&mut rng).0, token);
        assert_eq!(new_device_id(&mut rng).len(), 16);
    }

    #[test]
    fn constant_time_eq_compares_bytes() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn limiter_backs_off_after_free_attempts() {
        let limiter = LoginLimiter::default();
        for _ in 0..LoginLimiter::FREE_ATTEMPTS {
            assert!(limiter.check("a").is_ok());
            limiter.failed("a");
        }
        assert!(limiter.check("a").is_err());
        assert!(limiter.check("b").is_ok());
        limiter.succeeded("a");
        assert!(limiter.check("a").is_ok());
        assert_eq!(LoginLimiter::wait_after(5), Duration::from_secs(1));
        assert_eq!(LoginLimiter::wait_after(8), Duration::from_secs(8));
        assert_eq!(LoginLimiter::wait_after(100), LoginLimiter::MAX_WAIT);
    }

    #[test]
    fn limiter_stays_bounded_and_keeps_the_names_under_attack() {
        let limiter = LoginLimiter::with_capacity(100);
        for _ in 0..LoginLimiter::FREE_ATTEMPTS {
            limiter.failed("target");
        }
        for i in 0..10_000 {
            limiter.failed(&format!("nobody{i}"));
        }
        assert_eq!(limiter.len(), 100);
        // One-off names pushed each other out, not the guessed-at account.
        assert!(limiter.check("target").is_err());
    }
}
