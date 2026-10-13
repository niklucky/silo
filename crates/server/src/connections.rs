//! Mutual connections between accounts. One side asks, the other accepts;
//! only then does either see the other's keys or may grant them a secret.

use rusqlite::{Connection, OptionalExtension, params};
use silo_core::account::Identity;
use silo_core::crypto::PublicKey;
use silo_core::sync::{ConnectionInfo, ConnectionState};

use crate::auth::{Account, Auth};
use crate::error::{ApiError, ApiResult};

pub fn list(conn: &Connection, auth: &Auth) -> ApiResult<Vec<ConnectionInfo>> {
    let me = auth.account.id;
    let mut stmt = conn.prepare(&format!(
        "SELECT {}, c.requested_by, c.created_at, c.accepted_at
         FROM connections c
         JOIN accounts a ON a.id = CASE WHEN c.low_id = ?1 THEN c.high_id ELSE c.low_id END
         WHERE c.low_id = ?1 OR c.high_id = ?1
         ORDER BY a.username",
        Account::COLUMNS
    ))?;
    let rows = stmt.query_map([me], |row| {
        Ok(info(
            me,
            &Account::from_row(row)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        ))
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Asks `username` to connect, or accepts their request. Asking again is
/// harmless.
pub fn request(
    conn: &Connection,
    auth: &Auth,
    username: &str,
    now: u64,
) -> ApiResult<ConnectionInfo> {
    let me = auth.account.id;
    let other = find(conn, username)?;
    if other.id == me {
        return Err(ApiError::invalid("you cannot connect to yourself"));
    }
    let (low, high) = pair(me, other.id);
    let existing: Option<(i64, u64, Option<u64>)> = conn
        .query_row(
            "SELECT requested_by, created_at, accepted_at FROM connections
             WHERE low_id = ?1 AND high_id = ?2",
            [low, high],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (requested_by, created_at, accepted_at) = match existing {
        None => {
            conn.execute(
                "INSERT INTO connections (low_id, high_id, requested_by, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![low, high, me, now],
            )?;
            (me, now, None)
        }
        Some((by, created, None)) if by != me => {
            conn.execute(
                "UPDATE connections SET accepted_at = ?1 WHERE low_id = ?2 AND high_id = ?3",
                params![now, low, high],
            )?;
            (by, created, Some(now))
        }
        Some(row) => row,
    };
    Ok(info(me, &other, requested_by, created_at, accepted_at))
}

/// Cancels a request, declines one, or ends a connection. Secrets already
/// shared stay readable by the other side; new grants to them are refused.
pub fn remove(conn: &Connection, auth: &Auth, username: &str) -> ApiResult<()> {
    let other = find(conn, username)?;
    let (low, high) = pair(auth.account.id, other.id);
    let removed = conn.execute(
        "DELETE FROM connections WHERE low_id = ?1 AND high_id = ?2",
        [low, high],
    )?;
    if removed == 0 {
        return Err(ApiError::not_found(format!(
            "no connection with {}",
            other.username
        )));
    }
    Ok(())
}

/// True if `recipient` is the public key of an account connected to `me`.
pub fn is_connected_key(conn: &Connection, me: i64, recipient: &PublicKey) -> ApiResult<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (
            SELECT 1 FROM connections c
            JOIN accounts a ON a.id = CASE WHEN c.low_id = ?1 THEN c.high_id ELSE c.low_id END
            WHERE (c.low_id = ?1 OR c.high_id = ?1)
              AND c.accepted_at IS NOT NULL
              AND a.public_key = ?2)",
        params![me, &recipient.as_bytes()[..]],
        |row| row.get(0),
    )?)
}

fn find(conn: &Connection, username: &str) -> ApiResult<Account> {
    let username = silo_core::sync::normalize_username(username)
        .map_err(|err| ApiError::invalid(err.to_string()))?;
    conn.query_row(
        &format!(
            "SELECT {} FROM accounts a WHERE a.username = ?1",
            Account::COLUMNS
        ),
        [&username],
        Account::from_row,
    )
    .optional()?
    .ok_or_else(|| ApiError::not_found(format!("no account {username}")))
}

fn pair(a: i64, b: i64) -> (i64, i64) {
    (a.min(b), a.max(b))
}

fn info(
    me: i64,
    other: &Account,
    requested_by: i64,
    created_at: u64,
    accepted_at: Option<u64>,
) -> ConnectionInfo {
    let state = match (accepted_at, requested_by == me) {
        (Some(_), _) => ConnectionState::Connected,
        (None, true) => ConnectionState::Outgoing,
        (None, false) => ConnectionState::Incoming,
    };
    ConnectionInfo {
        username: other.username.clone(),
        state,
        identity: accepted_at.map(|_| Identity {
            public_key: other.public_key,
            signing_key: other.signing_key,
        }),
        created_at,
        accepted_at,
    }
}
