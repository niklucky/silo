//! Push and pull. The server checks what it can without keys: signatures,
//! ownership, revision order and who grants go to. It cannot read anything,
//! and clients verify signatures again themselves.

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use silo_core::sync::{
    Change, ChangesReply, HistoryReply, HistoryRequest, PushItem, PushReply, PushRequest,
    PushResult, Tombstone,
};
use silo_core::vault::{Grant, SealedSecret, StoredSecret};

use crate::accounts;
use crate::auth::{Account, Auth};
use crate::connections;
use crate::error::{ApiError, ApiResult};

pub const MAX_PUSH_ITEMS: usize = 500;
pub const DEFAULT_CHANGES_LIMIT: usize = 200;
pub const MAX_CHANGES_LIMIT: usize = 1000;
pub const MAX_HISTORY_QUERIES: usize = 500;
pub const MAX_HISTORY_REVISIONS: usize = 1000;

/// Applies every item in one transaction. Each gets its own result; a
/// conflict or rejection does not stop the others.
pub fn push(
    conn: &mut Connection,
    auth: &Auth,
    now: u64,
    request: PushRequest,
) -> ApiResult<PushReply> {
    if request.items.len() > MAX_PUSH_ITEMS {
        return Err(ApiError::invalid(format!(
            "at most {MAX_PUSH_ITEMS} items per push"
        )));
    }
    let tx = conn.transaction()?;
    let mut results = Vec::with_capacity(request.items.len());
    for item in request.items {
        results.push(match item {
            PushItem::Put {
                base_revision,
                entry,
                restore,
            } => put(&tx, &auth.account, now, base_revision, entry, restore)?,
            PushItem::Delete { tombstone } => delete(&tx, &auth.account, tombstone)?,
        });
    }
    tx.commit()?;
    Ok(PushReply { results })
}

/// Secrets this account holds a grant for, changed after `since`, oldest first.
pub fn changes(
    conn: &Connection,
    auth: &Auth,
    since: u64,
    limit: Option<usize>,
) -> ApiResult<ChangesReply> {
    let limit = limit
        .unwrap_or(DEFAULT_CHANGES_LIMIT)
        .clamp(1, MAX_CHANGES_LIMIT);
    let me = &auth.account;
    let mut stmt = conn.prepare(
        "SELECT s.id, s.owner_id, s.current_revision, s.tombstone, s.seq FROM secrets s
         WHERE s.seq > ?1 AND EXISTS (
             SELECT 1 FROM grants g
             WHERE g.secret_id = s.id AND g.revision = s.current_revision AND g.recipient = ?2)
         ORDER BY s.seq LIMIT ?3",
    )?;
    let mut rows = stmt
        .query_map(
            params![since, &me.public_key.as_bytes()[..], limit + 1],
            |row| Ok((row.get::<_, String>(0)?, SecretRow::from_row(row, 1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let more = rows.len() > limit;
    rows.truncate(limit);

    let mut changes = Vec::with_capacity(rows.len());
    for (id, row) in &rows {
        changes.push(current_change(conn, id, row, me)?);
    }
    // With nothing more to send, every visible change up to the newest seq is
    // in this reply, so the cursor can jump there. A cursor below `since`
    // tells the client the server lost data (a restored backup): pull from 0.
    let cursor = if more {
        rows.last().map_or(since, |(_, row)| row.seq)
    } else {
        max_seq(conn)?
    };
    Ok(ChangesReply {
        changes,
        cursor,
        more,
        account_version: accounts::account_version(conn, me.id)?,
    })
}

/// Revisions between two numbers for each query, as far as the account
/// holds a grant for them. Owners see every grant, others only their own.
pub fn history(conn: &Connection, auth: &Auth, request: HistoryRequest) -> ApiResult<HistoryReply> {
    if request.items.len() > MAX_HISTORY_QUERIES {
        return Err(ApiError::invalid(format!(
            "at most {MAX_HISTORY_QUERIES} queries per request"
        )));
    }
    let me = &auth.account;
    let mut revisions = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT r.revision, r.data, s.owner_id FROM revisions r JOIN secrets s ON s.id = r.secret_id
         WHERE r.secret_id = ?1 AND r.revision > ?2 AND r.revision < ?3
           AND EXISTS (SELECT 1 FROM grants g
                       WHERE g.secret_id = r.secret_id AND g.revision = r.revision
                         AND g.recipient = ?4)
         ORDER BY r.revision",
    )?;
    for query in &request.items {
        let id = query.secret_id.to_string();
        let rows = stmt
            .query_map(
                params![id, query.after, query.before, &me.public_key.as_bytes()[..]],
                |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        for (revision, data, owner_id) in rows {
            if revisions.len() >= MAX_HISTORY_REVISIONS {
                return Ok(HistoryReply { revisions });
            }
            let secret: SealedSecret = serde_json::from_str(&data)?;
            let grants = grants_for(conn, &id, revision, owner_id != me.id, me)?;
            revisions.push(StoredSecret { secret, grants });
        }
    }
    Ok(HistoryReply { revisions })
}

struct SecretRow {
    owner_id: i64,
    current_revision: u32,
    tombstone: Option<String>,
    seq: u64,
}

impl SecretRow {
    fn from_row(row: &rusqlite::Row<'_>, first: usize) -> rusqlite::Result<Self> {
        Ok(Self {
            owner_id: row.get(first)?,
            current_revision: row.get(first + 1)?,
            tombstone: row.get(first + 2)?,
            seq: row.get(first + 3)?,
        })
    }
}

fn secret_row(conn: &Connection, id: &str) -> ApiResult<Option<SecretRow>> {
    Ok(conn
        .query_row(
            "SELECT owner_id, current_revision, tombstone, seq FROM secrets WHERE id = ?1",
            [id],
            |row| SecretRow::from_row(row, 0),
        )
        .optional()?)
}

fn put(
    tx: &Transaction<'_>,
    me: &Account,
    now: u64,
    base_revision: u32,
    entry: StoredSecret,
    restore: bool,
) -> ApiResult<PushResult> {
    if entry.verify(&me.signing_key).is_err() {
        return rejected("the revision or a grant is not signed by this account");
    }
    let revision = entry.secret.revision;
    if revision == 0 {
        return rejected("revisions start at 1");
    }
    let mut recipients = BTreeSet::new();
    for grant in &entry.grants {
        if !recipients.insert(grant.recipient) {
            return rejected("two grants for the same recipient");
        }
    }
    if !recipients.contains(&me.public_key) {
        return rejected("the owner has no grant of their own");
    }
    for recipient in recipients.iter().filter(|r| **r != me.public_key) {
        if !connections::is_connected_key(tx, me.id, recipient)? {
            return rejected("a grant goes to an account you are not connected with");
        }
    }

    let id = entry.secret.id.to_string();
    let seq = next_seq(tx)?;
    match secret_row(tx, &id)? {
        Some(row) if row.owner_id != me.id => {
            return rejected("this secret belongs to another account");
        }
        // A stale base, an edit that has not seen the deletion, or a restore
        // of something that is no longer deleted.
        Some(row)
            if row.current_revision != base_revision || row.tombstone.is_some() != restore =>
        {
            return conflict(tx, &id, &row, me);
        }
        Some(row) if revision <= row.current_revision => {
            return rejected("the new revision must be newer than its base");
        }
        Some(_) => {
            tx.execute(
                "UPDATE secrets SET current_revision = ?1, tombstone = NULL, seq = ?2 WHERE id = ?3",
                params![revision, seq, id],
            )?;
        }
        // Nothing to conflict with: a new secret, or one this server never saw.
        None => {
            tx.execute(
                "INSERT INTO secrets (id, owner_id, current_revision, seq) VALUES (?1, ?2, ?3, ?4)",
                params![id, me.id, revision, seq],
            )?;
        }
    }
    tx.execute(
        "INSERT INTO revisions (secret_id, revision, author_id, data, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            id,
            revision,
            me.id,
            serde_json::to_string(&entry.secret)?,
            now
        ],
    )?;
    for grant in &entry.grants {
        tx.execute(
            "INSERT INTO grants (secret_id, revision, recipient, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                id,
                revision,
                &grant.recipient.as_bytes()[..],
                serde_json::to_string(grant)?
            ],
        )?;
    }
    Ok(PushResult::Ok { seq })
}

fn delete(tx: &Transaction<'_>, me: &Account, tombstone: Tombstone) -> ApiResult<PushResult> {
    if tombstone.verify(&me.signing_key).is_err() {
        return rejected("the tombstone is not signed by this account");
    }
    let id = tombstone.secret_id.to_string();
    let Some(row) = secret_row(tx, &id)? else {
        return rejected("this server has no such secret");
    };
    if row.owner_id != me.id {
        return rejected("this secret belongs to another account");
    }
    let already = match &row.tombstone {
        Some(json) => Some(serde_json::from_str::<Tombstone>(json)?),
        None => None,
    };
    match already {
        // Sent twice: the first one counted.
        Some(existing) if existing.revision == tombstone.revision => {
            return Ok(PushResult::Ok { seq: row.seq });
        }
        Some(_) => {
            return conflict(tx, &id, &row, me);
        }
        None if tombstone.revision != row.current_revision => {
            return conflict(tx, &id, &row, me);
        }
        None => {}
    }
    let seq = next_seq(tx)?;
    tx.execute(
        "UPDATE secrets SET tombstone = ?1, seq = ?2 WHERE id = ?3",
        params![serde_json::to_string(&tombstone)?, seq, id],
    )?;
    Ok(PushResult::Ok { seq })
}

/// What `viewer` gets to see of a secret now. The owner sees every grant;
/// anyone else only their own, not who else it is shared with.
fn current_change(
    conn: &Connection,
    id: &str,
    row: &SecretRow,
    viewer: &Account,
) -> ApiResult<Change> {
    if let Some(json) = &row.tombstone {
        return Ok(Change::Delete {
            seq: row.seq,
            tombstone: serde_json::from_str(json)?,
        });
    }
    let data: String = conn.query_row(
        "SELECT data FROM revisions WHERE secret_id = ?1 AND revision = ?2",
        params![id, row.current_revision],
        |r| r.get(0),
    )?;
    let secret: SealedSecret = serde_json::from_str(&data)?;
    let grants = grants_for(
        conn,
        id,
        row.current_revision,
        row.owner_id != viewer.id,
        viewer,
    )?;
    Ok(Change::Put {
        seq: row.seq,
        entry: StoredSecret { secret, grants },
    })
}

fn grants_for(
    conn: &Connection,
    id: &str,
    revision: u32,
    only_mine: bool,
    viewer: &Account,
) -> ApiResult<Vec<Grant>> {
    let mut stmt = conn.prepare_cached(
        "SELECT data FROM grants
         WHERE secret_id = ?1 AND revision = ?2 AND (?3 = 0 OR recipient = ?4)
         ORDER BY recipient",
    )?;
    stmt.query_map(
        params![id, revision, only_mine, &viewer.public_key.as_bytes()[..]],
        |r| r.get::<_, String>(0),
    )?
    .map(|json| Ok(serde_json::from_str::<Grant>(&json?)?))
    .collect()
}

fn next_seq(conn: &Connection) -> ApiResult<u64> {
    Ok(max_seq(conn)? + 1)
}

fn max_seq(conn: &Connection) -> ApiResult<u64> {
    Ok(
        conn.query_row("SELECT COALESCE(MAX(seq), 0) FROM secrets", [], |row| {
            row.get(0)
        })?,
    )
}

fn conflict(conn: &Connection, id: &str, row: &SecretRow, me: &Account) -> ApiResult<PushResult> {
    Ok(PushResult::Conflict {
        current: Box::new(current_change(conn, id, row, me)?),
    })
}

fn rejected(message: &str) -> ApiResult<PushResult> {
    Ok(PushResult::Rejected {
        message: message.to_owned(),
    })
}
