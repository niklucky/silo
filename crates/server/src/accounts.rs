//! Invites, registration, login, devices.

use hkdf::Hkdf;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::Sha256;
use silo_core::account::{AccountRecord, Identity};
use silo_core::crypto::{CryptoRng, KdfAlgorithm, KdfParams};
use silo_core::sync::{
    self, AccountReply, DeviceInfo, ErrorCode, LoginRequest, PreloginReply, RegisterRequest,
    SessionReply,
};

use crate::auth::{self, Account, Auth, LoginLimiter, constant_time_eq, sha256};
use crate::db;
use crate::error::{ApiError, ApiResult};

pub const DEVICE_NAME_MAX_LEN: usize = 64;

/// Base32 without look-alikes (Crockford), lowercase.
const INVITE_ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Creates a one-time invite valid for `days` and returns its code, e.g.
/// `k3f9q-2xw7m-p4hzc-8vd1n`. Only its hash is stored.
pub fn create_invite(
    conn: &Connection,
    rng: &mut impl CryptoRng,
    now: u64,
    days: u64,
) -> ApiResult<String> {
    let mut bytes = [0u8; 20];
    rng.fill_bytes(&mut bytes);
    let chars: Vec<u8> = bytes
        .iter()
        .map(|b| INVITE_ALPHABET[usize::from(b % 32)])
        .collect();
    let code = chars
        .chunks(5)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-");
    conn.execute(
        "INSERT INTO invites (code_hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
        params![
            &invite_hash(&code)[..],
            now,
            now.saturating_add(days.saturating_mul(86_400))
        ],
    )?;
    Ok(code)
}

fn invite_hash(code: &str) -> [u8; 32] {
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    sha256(normalized.as_bytes())
}

pub fn prelogin(conn: &Connection, username: &str) -> ApiResult<PreloginReply> {
    let username = normalize(username)?;
    let record: Option<String> = conn
        .query_row(
            "SELECT record FROM accounts WHERE username = ?1",
            [&username],
            |row| row.get(0),
        )
        .optional()?;
    let kdf = match record {
        Some(json) => serde_json::from_str::<AccountRecord>(&json)?.kdf,
        None => made_up_kdf(conn, &username)?,
    };
    Ok(PreloginReply { kdf })
}

/// Recommended parameters with a salt derived from the server's secret and
/// the username: stable for one name, different between names, like real ones.
fn made_up_kdf(conn: &Connection, username: &str) -> ApiResult<KdfParams> {
    let secret = db::setting(conn, db::PRELOGIN_SECRET)?
        .ok_or_else(|| ApiError::internal("prelogin secret missing"))?;
    let mut salt = [0u8; 16];
    Hkdf::<Sha256>::new(Some(&secret), username.as_bytes())
        .expand(b"silo/v1/prelogin-salt", &mut salt)
        .map_err(ApiError::internal)?;
    Ok(KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib: KdfParams::RECOMMENDED_MEMORY_KIB,
        iterations: KdfParams::RECOMMENDED_ITERATIONS,
        parallelism: KdfParams::RECOMMENDED_PARALLELISM,
        salt,
    })
}

pub fn register(
    conn: &mut Connection,
    rng: &mut impl CryptoRng,
    now: u64,
    request: RegisterRequest,
) -> ApiResult<SessionReply> {
    let username = normalize(&request.username)?;
    let device_name = device_name(&request.device_name)?;
    request
        .account
        .kdf
        .check_minimum()
        .map_err(|err| ApiError::invalid(err.to_string()))?;
    if request.account.public_key != request.identity.public_key {
        return Err(ApiError::invalid(
            "the account record and the identity name different public keys",
        ));
    }
    sync::verify_registration(&request.identity, &username, &request.proof)
        .map_err(|_| ApiError::invalid("the registration proof does not verify"))?;

    let tx = conn.transaction()?;
    let invite = invite_hash(&request.invite);
    let valid: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM invites
             WHERE code_hash = ?1 AND used_by IS NULL AND expires_at > ?2)",
        params![&invite[..], now],
        |row| row.get(0),
    )?;
    if !valid {
        return Err(ApiError::new(
            ErrorCode::InviteInvalid,
            "unknown, used or expired invite",
        ));
    }
    let taken = |sql: &str, value: &dyn rusqlite::ToSql| -> ApiResult<bool> {
        Ok(tx.query_row(sql, [value], |row| row.get(0))?)
    };
    if taken(
        "SELECT EXISTS (SELECT 1 FROM accounts WHERE username = ?1)",
        &username,
    )? {
        return Err(ApiError::new(
            ErrorCode::UsernameTaken,
            format!("{username} is taken"),
        ));
    }
    let identity = request.identity;
    if taken(
        "SELECT EXISTS (SELECT 1 FROM accounts WHERE public_key = ?1 OR signing_key = ?1)",
        &&identity.public_key.as_bytes()[..],
    )? || taken(
        "SELECT EXISTS (SELECT 1 FROM accounts WHERE public_key = ?1 OR signing_key = ?1)",
        &&identity.signing_key.as_bytes()[..],
    )? {
        return Err(ApiError::new(
            ErrorCode::IdentityTaken,
            "these keys already belong to an account",
        ));
    }

    tx.execute(
        "INSERT INTO accounts
         (username, public_key, signing_key, record, record_version, auth_hash, created_at)
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)",
        params![
            username,
            &identity.public_key.as_bytes()[..],
            &identity.signing_key.as_bytes()[..],
            serde_json::to_string(&request.account)?,
            &sha256(request.auth_key.as_bytes())[..],
            now
        ],
    )?;
    let account_id = tx.last_insert_rowid();
    tx.execute(
        "UPDATE invites SET used_by = ?1, used_at = ?2 WHERE code_hash = ?3",
        params![account_id, now, &invite[..]],
    )?;
    let reply = new_session(&tx, rng, now, account_id, &device_name)?;
    tx.commit()?;
    Ok(reply)
}

pub fn login(
    conn: &mut Connection,
    limiter: &LoginLimiter,
    rng: &mut impl CryptoRng,
    now: u64,
    request: LoginRequest,
) -> ApiResult<SessionReply> {
    let wrong = || ApiError::new(ErrorCode::Unauthorized, "wrong username or password");
    let username = normalize(&request.username).map_err(|_| wrong())?;
    let device_name = device_name(&request.device_name)?;
    limiter.check(&username)?;

    let found: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT id, auth_hash FROM accounts WHERE username = ?1",
            [&username],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let presented = sha256(request.auth_key.as_bytes());
    // Compare against something either way, so a missing account takes as long.
    let (account_id, stored) = found.unwrap_or((0, vec![0; 32]));
    if account_id == 0 || !constant_time_eq(&presented, &stored) {
        limiter.failed(&username);
        return Err(wrong());
    }
    limiter.succeeded(&username);

    let tx = conn.transaction()?;
    let reply = new_session(&tx, rng, now, account_id, &device_name)?;
    tx.commit()?;
    Ok(reply)
}

fn new_session(
    conn: &Connection,
    rng: &mut impl CryptoRng,
    now: u64,
    account_id: i64,
    device_name: &str,
) -> ApiResult<SessionReply> {
    let device_id = auth::new_device_id(rng);
    let (token, token_hash) = auth::new_token(rng);
    conn.execute(
        "INSERT INTO devices (id, account_id, name, token_hash, created_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![device_id, account_id, device_name, &token_hash[..], now],
    )?;
    Ok(SessionReply {
        device_id,
        token,
        account: account_reply(conn, account_id)?,
    })
}

pub fn account_reply(conn: &Connection, account_id: i64) -> ApiResult<AccountReply> {
    let (account, record, version): (Account, String, u32) = conn.query_row(
        &format!(
            "SELECT {}, a.record, a.record_version FROM accounts a WHERE a.id = ?1",
            Account::COLUMNS
        ),
        [account_id],
        |row| Ok((Account::from_row(row)?, row.get(4)?, row.get(5)?)),
    )?;
    Ok(AccountReply {
        username: account.username,
        account: serde_json::from_str(&record)?,
        identity: Identity {
            public_key: account.public_key,
            signing_key: account.signing_key,
        },
        account_version: version,
    })
}

pub fn account_version(conn: &Connection, account_id: i64) -> ApiResult<u32> {
    Ok(conn.query_row(
        "SELECT record_version FROM accounts WHERE id = ?1",
        [account_id],
        |row| row.get(0),
    )?)
}

pub fn devices(conn: &Connection, auth: &Auth) -> ApiResult<Vec<DeviceInfo>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, created_at, last_seen_at FROM devices
         WHERE account_id = ?1 ORDER BY created_at, id",
    )?;
    let rows = stmt.query_map([auth.account.id], |row| {
        let id: String = row.get(0)?;
        Ok(DeviceInfo {
            current: id == auth.device_id,
            id,
            name: row.get(1)?,
            created_at: row.get(2)?,
            last_seen_at: row.get(3)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Revokes one of the account's devices; its token stops working at once.
pub fn revoke_device(conn: &Connection, auth: &Auth, device_id: &str) -> ApiResult<()> {
    let removed = conn.execute(
        "DELETE FROM devices WHERE id = ?1 AND account_id = ?2",
        params![device_id, auth.account.id],
    )?;
    if removed == 0 {
        return Err(ApiError::not_found(format!("no device {device_id}")));
    }
    Ok(())
}

fn normalize(username: &str) -> ApiResult<String> {
    sync::normalize_username(username).map_err(|err| ApiError::invalid(err.to_string()))
}

fn device_name(name: &str) -> ApiResult<String> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > DEVICE_NAME_MAX_LEN
        || name.chars().any(char::is_control)
    {
        return Err(ApiError::invalid(format!(
            "device name must be 1 to {DEVICE_NAME_MAX_LEN} printable characters"
        )));
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_codes_are_grouped_and_forgiving() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let code = db
            .with(|conn| create_invite(conn, &mut rand::rng(), 0, 7))
            .unwrap();
        assert_eq!(code.len(), 23);
        assert_eq!(code.matches('-').count(), 3);
        assert_eq!(
            invite_hash(&code),
            invite_hash(&code.to_uppercase().replace('-', " "))
        );
    }
}
