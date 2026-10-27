//! One sync run: pull everything new, then push local changes in rounds.
//!
//! Conflicts never lose an edit. When a secret changed both here and on the
//! server, the newer edit (by its `updated_at`) becomes the current revision
//! and the other one stays in history, here and on the server:
//!
//! ```text
//! server:  … R            (theirs)
//! yours newer:   R → R+1 = yours
//! theirs newer:  R → R+1 = yours → R+2 = theirs again
//! ```
//!
//! "Yours" is every revision made here since the last sync, renumbered in
//! order on top of R, not just the latest.
//!
//! An edit also wins over a deletion, whichever side made which; local edits
//! are renumbered on top of the deleted revision the same way.

use serde::{Deserialize, Serialize};
use silo_core::crypto::{CryptoRng, PublicKey};
use silo_core::sync::{
    Change, HistoryQuery, HistoryRequest, PushItem, PushRequest, PushResult, Tombstone,
};
use silo_core::vault::{SecretId, SecretMeta, StoredSecret};

use super::SyncError;
use super::http::HttpClient;
use super::state::{Rejection, SyncState};
use crate::session::Session;
use crate::store::Store;

/// Items per push request; large file secrets make batches big.
pub const PUSH_BATCH: usize = 100;
/// Each round pushes at most one revision per secret, so a secret with a
/// chain of local revisions needs a round for each.
const MAX_ROUNDS: usize = 8;

/// What one run did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    /// Secrets added or changed from the server.
    pub pulled: usize,
    /// Secrets deleted because they were deleted elsewhere.
    pub removed: usize,
    /// Revisions and deletions the server accepted.
    pub pushed: usize,
    /// Conflict/recovery notices, including undelivered notices from failed runs.
    pub conflicts: Vec<String>,
    /// One line per change the server refused.
    pub rejected: Vec<String>,
    /// Changes not signed by their trusted owner, or that could not be opened.
    /// Ignored until the owner is explicitly verified.
    pub skipped: usize,
}

/// A run in progress: when it started, what it did so far, and the revisions
/// it skipped over that should go into local history.
#[derive(Default)]
struct Progress {
    now: u64,
    report: SyncReport,
    gaps: Vec<HistoryQuery>,
}

impl Progress {
    /// Revisions between `known` and `received` went by on the server without
    /// this device seeing them.
    fn gap(&mut self, id: SecretId, known: Option<u32>, received: u32) {
        if let Some(known) = known
            && received > known.saturating_add(1)
        {
            self.gaps.push(HistoryQuery {
                secret_id: id,
                after: known,
                before: received,
            });
        }
    }
}

/// Everything a run touches, borrowed under the agent's lock.
pub struct Vault<'a> {
    pub store: &'a Store,
    pub session: &'a mut Session,
    pub state: &'a mut SyncState,
}

impl Vault<'_> {
    pub fn save(&self) -> Result<(), SyncError> {
        Ok(self.store.write_sync(self.state)?)
    }
}

/// Lends the vault to the engine for one step at a time, so the agent's lock
/// is never held during network calls.
pub trait VaultAccess {
    /// Fails with [`SyncError::Locked`] or [`SyncError::NotConfigured`].
    fn with_vault<R>(
        &self,
        f: impl FnOnce(&mut Vault<'_>) -> Result<R, SyncError>,
    ) -> Result<R, SyncError>;
}

/// Runs one sync and records its outcome in the sync state.
pub fn run(access: &impl VaultAccess, now: &dyn Fn() -> u64) -> Result<SyncReport, SyncError> {
    let client =
        access.with_vault(|v| Ok(HttpClient::new(&v.state.server)?.with_token(&v.state.token)))?;
    let mut progress = Progress {
        now: now(),
        report: SyncReport {
            conflicts: access.with_vault(|v| Ok(v.store.read_conflict_notices()?))?,
            ..SyncReport::default()
        },
        ..Progress::default()
    };
    let result = run_with(access, &client, &mut progress);
    let error = result.as_ref().err().map(ToString::to_string);
    let recorded = access.with_vault(|v| {
        if error.is_none() {
            v.state.last_sync = Some(now());
        }
        v.state.last_error = error;
        v.save()
    });
    let with_recovery = |error| {
        if progress.report.conflicts.is_empty() {
            error
        } else {
            SyncError::Recovery {
                error: Box::new(error),
                notices: progress.report.conflicts.join("\n"),
            }
        }
    };
    result.map_err(with_recovery)?;
    recorded.map_err(with_recovery)?;
    // A later network/storage failure cannot consume a notice. Clear the
    // durable outbox only after all sync steps and final status persistence
    // succeeded; the caller receives the accumulated report or an error that
    // also includes its recovery paths.
    access
        .with_vault(|v| Ok(v.store.clear_conflict_notices()?))
        .map_err(with_recovery)?;
    Ok(progress.report)
}

fn run_with(
    access: &impl VaultAccess,
    client: &HttpClient,
    progress: &mut Progress,
) -> Result<(), SyncError> {
    let mut rng = rand::rng();

    loop {
        let since = access.with_vault(|v| Ok(v.state.cursor))?;
        let reply = client.changes(since)?;
        let more = access.with_vault(|v| {
            let more = if reply.cursor < since {
                // The server has less than we pulled: it was restored from an
                // older backup. Start over; anything it lacks is pushed again.
                v.state.cursor = 0;
                v.state.known.clear();
                v.state.deleted_remotely.clear();
                true
            } else {
                for change in reply.changes {
                    apply_change(v, &mut rng, change, progress)?;
                }
                v.state.cursor = reply.cursor;
                v.state.account_version = reply.account_version;
                reply.more
            };
            v.save()?;
            Ok(more)
        })?;
        if !more {
            break;
        }
    }
    // Every upload that reached the server was in that pull.
    access.with_vault(|v| {
        v.state.in_flight.clear();
        v.save()
    })?;

    for _ in 0..MAX_ROUNDS {
        let items = access.with_vault(plan_push)?;
        if items.is_empty() {
            break;
        }
        for chunk in items.chunks(PUSH_BATCH) {
            access.with_vault(|v| {
                begin_push(v, chunk);
                v.save()
            })?;
            let reply = client.push(&PushRequest {
                items: chunk.to_vec(),
            })?;
            if reply.results.len() != chunk.len() {
                return Err(SyncError::Protocol(format!(
                    "{} results for {} items",
                    reply.results.len(),
                    chunk.len()
                )));
            }
            access.with_vault(|v| {
                for (item, result) in chunk.iter().zip(reply.results) {
                    apply_result(v, &mut rng, item, result, progress)?;
                }
                v.save()
            })?;
        }
    }
    fill_gaps(access, client, std::mem::take(&mut progress.gaps));
    Ok(())
}

/// Fetches the revisions a run skipped over and keeps them in history.
/// Best effort: history is a convenience, so failures are ignored.
fn fill_gaps(access: &impl VaultAccess, client: &HttpClient, gaps: Vec<HistoryQuery>) {
    for chunk in gaps.chunks(200) {
        let Ok(reply) = client.history(&HistoryRequest {
            items: chunk.to_vec(),
        }) else {
            return;
        };
        let _ = access.with_vault(|v| {
            for stored in reply.revisions {
                let id = stored.secret.id;
                if !v.session.is_local_only(id)
                    && v.session.stored(id).is_some()
                    && !v.store.has_archived(id, stored.secret.revision)
                    && v.session.trusted_revision(&stored)
                    && v.session.open_parts(&stored).is_ok()
                {
                    v.store.archive(&stored)?;
                }
            }
            Ok(())
        });
    }
}

fn record_conflict(
    v: &Vault<'_>,
    progress: &mut Progress,
    notice: String,
) -> Result<(), SyncError> {
    if !progress.report.conflicts.contains(&notice) {
        progress.report.conflicts.push(notice);
    }
    v.store.write_conflict_notices(&progress.report.conflicts)?;
    Ok(())
}

/// Brings one change from the server into the local vault.
fn apply_change(
    v: &mut Vault<'_>,
    rng: &mut impl CryptoRng,
    change: Change,
    progress: &mut Progress,
) -> Result<(), SyncError> {
    match change {
        Change::Put { entry, .. } => apply_put(v, rng, entry, progress),
        Change::Delete { tombstone, .. } => apply_delete(v, rng, tombstone, progress),
    }
}

fn apply_put(
    v: &mut Vault<'_>,
    rng: &mut impl CryptoRng,
    remote: StoredSecret,
    progress: &mut Progress,
) -> Result<(), SyncError> {
    let id = remote.secret.id;
    let revision = remote.secret.revision;
    if v.session.is_local_only(id) {
        progress.report.skipped += 1;
        return Ok(());
    }
    // Accept only signatures from the bound owner or an explicitly pinned peer.
    if !v.session.trusted_revision(&remote) || v.session.open_parts(&remote).is_err() {
        progress.report.skipped += 1;
        return Ok(());
    }
    let known = v.state.known.get(&id).copied();

    let uploaded_here = v.state.in_flight.get(&id) == Some(&digest_hex(&remote));
    if let Some(deleted) = v.state.deletes.get(&id) {
        if revision > deleted.revision && uploaded_here {
            // This device's own upload, sent before the deletion: the
            // deletion covers it.
            let tombstone = v.session.tombstone(id, revision, progress.now);
            v.state.deletes.insert(id, tombstone);
        } else if revision > deleted.revision {
            // Edited elsewhere after the revision deleted here: the edit wins.
            v.state.deletes.remove(&id);
            v.session.accept(v.store, remote, false)?;
            v.state.known.insert(id, revision);
            progress.report.pulled += 1;
            record_conflict(
                v,
                progress,
                format!(
                    "{}: deleted here but changed on another device; kept their version",
                    path(v, id)
                ),
            )?;
        }
        return Ok(());
    }
    v.state.deleted_remotely.remove(&id);

    let Some(local) = v.session.stored(id) else {
        if uploaded_here {
            // Uploaded from here and deleted before the server confirmed it.
            v.state.known.remove(&id);
            let tombstone = v.session.tombstone(id, revision, progress.now);
            v.state.deletes.insert(id, tombstone);
            return Ok(());
        }
        v.session.accept(v.store, remote, false)?;
        v.state.known.insert(id, revision);
        progress.report.pulled += 1;
        return Ok(());
    };
    if local.secret.digest() == remote.secret.digest() {
        v.state.known.insert(id, revision);
        return Ok(());
    }
    if known.is_some_and(|k| revision <= k) {
        // Older than what this device has already seen: a server rolling a
        // secret back. Ignore it.
        progress.report.skipped += 1;
        return Ok(());
    }
    if v.store
        .history(id)?
        .iter()
        .any(|h| h.secret.revision == revision && h.secret.digest() == remote.secret.digest())
    {
        // A revision made here, which reached the server without this device
        // hearing back; the ones after it are still to send.
        v.state.known.insert(id, revision);
        return Ok(());
    }
    if !v.session.is_owned(id) {
        if revision <= local.secret.revision {
            progress.report.skipped += 1;
            return Ok(());
        }
        progress.gap(id, Some(local.secret.revision), revision);
        v.session.accept(v.store, remote, true)?;
        v.state.known.insert(id, revision);
        progress.report.pulled += 1;
        return Ok(());
    }
    if known == Some(local.secret.revision) {
        progress.gap(id, known, revision);
        v.session.accept(v.store, remote, true)?;
        v.state.known.insert(id, revision);
        progress.report.pulled += 1;
        return Ok(());
    }
    resolve_conflict(v, rng, remote, progress)
}

/// The secret changed here and on the server. Both versions end up in history
/// on top of the server's revision, the newer edit last.
fn resolve_conflict(
    v: &mut Vault<'_>,
    rng: &mut impl CryptoRng,
    remote: StoredSecret,
    progress: &mut Progress,
) -> Result<(), SyncError> {
    let id = remote.secret.id;
    let base = remote.secret.revision;
    let (theirs_meta, theirs_body) = v.session.open_parts(&remote)?;
    if matches!(theirs_body, silo_core::vault::SecretBody::File(_)) {
        return preserve_file_conflict(v, rng, remote, progress);
    }

    let known = v.state.known.get(&id).copied();
    let after = match known {
        Some(known) => known,
        // No baseline: never synced from here, or the server lost data. A
        // revision made here may have the number the server gave theirs.
        None if v.store.has_archived(id, base) => base.saturating_sub(1),
        None => base,
    };
    progress.gap(id, known, base);
    let recipients: Vec<_> = remote.grants.iter().map(|g| g.recipient).collect();
    let (mine, mine_meta) = rebase_local(v, rng, id, after, base, 1, &recipients)?;
    v.store.archive(&remote)?;
    let outcome = if mine_meta.updated_at > theirs_meta.updated_at {
        "kept yours, theirs is in history"
    } else {
        v.session
            .reseal(v.store, rng, id, mine + 1, &theirs_meta, &theirs_body, true)?;
        "kept theirs, yours is in history"
    };
    v.state.known.insert(id, base);
    record_conflict(
        v,
        progress,
        format!(
            "{}: changed here and on another device; {outcome}",
            path(v, id)
        ),
    )?;
    Ok(())
}

/// Keep file conflicts private until the user deliberately publishes a chosen
/// version. Never temporarily upload stale file contents as the current server
/// revision while replaying offline history.
fn preserve_file_conflict(
    v: &mut Vault<'_>,
    rng: &mut impl CryptoRng,
    remote: StoredSecret,
    progress: &mut Progress,
) -> Result<(), SyncError> {
    let id = remote.secret.id;
    let known = v.state.known.get(&id).copied();
    let (copy, archived_revisions) = save_local_file_copy(v, rng, id, progress.now)?;
    let revision = remote.secret.revision;
    progress.gap(id, known, revision);
    record_conflict(
        v,
        progress,
        format!(
            "{}: kept the server version; local edits and history saved privately as {} (id {}); export that copy to review and apply with `silo edit --file`",
            path(v, id),
            copy.path(),
            copy.id
        ),
    )?;
    // Remove old number collisions only after their private replacement and
    // recovery notice are durable. A cleanup error must retain the copy's path.
    for revision in archived_revisions {
        v.store.unarchive(id, revision)?;
    }
    v.session.accept(v.store, remote, false)?;
    v.state.known.insert(id, revision);
    v.state.rejected.remove(&id);
    progress.report.pulled += 1;

    Ok(())
}

fn save_local_file_copy(
    v: &mut Vault<'_>,
    rng: &mut impl CryptoRng,
    id: SecretId,
    now: u64,
) -> Result<(crate::protocol::SecretSummary, Vec<u32>), SyncError> {
    use crate::protocol::{NewSecret, SecretUpdate};
    let known = v.state.known.get(&id).copied();
    let current = v
        .session
        .stored(id)
        .cloned()
        .expect("conflicting file exists");
    let (meta, _) = v.session.open_parts(&current)?;
    let mut chain: Vec<_> = v
        .store
        .history(id)?
        .into_iter()
        .filter(|s| {
            s.secret.revision > known.unwrap_or(0) && s.secret.revision < current.secret.revision
        })
        .collect();
    chain.reverse();
    chain.push(current);
    let mut suffix = [0u8; 4];
    rng.fill_bytes(&mut suffix);
    let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let mut copy: Option<crate::protocol::SecretSummary> = None;
    // Persist every offline revision under a new, private id before replacing
    // or removing any of the original records.
    for stored in &chain {
        let (_, body) = v.session.open_parts(stored)?;
        copy = Some(match copy {
            None => v.session.add_local(
                v.store,
                rng,
                now,
                NewSecret {
                    title: format!("{} (conflict {suffix})", meta.title),
                    folder: meta.folder.clone(),
                    tags: meta.tags.clone(),
                    urls: meta.urls.clone(),
                    basic_auth: false,
                    body,
                },
            )?,
            Some(ref previous) => v.session.update(
                v.store,
                rng,
                now,
                SecretUpdate {
                    selector: previous.id.to_string(),
                    revision: Some(previous.revision),
                    title: None,
                    folder: None,
                    tags: None,
                    urls: None,
                    basic_auth: None,
                    body: Some(body),
                },
            )?,
        });
    }
    let copy = copy.expect("chain includes current file");
    Ok((copy, chain.iter().map(|s| s.secret.revision).collect()))
}

/// Moves the revisions made here after `after` on top of the server's
/// `base`, oldest first, so none shares a number with a revision from
/// elsewhere: they become `base + 1`, `base + 2`, … and the newest stays
/// current. `spare` more numbers must be left after it. Returns the newest's
/// revision and meta.
fn rebase_local(
    v: &mut Vault<'_>,
    rng: &mut impl CryptoRng,
    id: SecretId,
    after: u32,
    base: u32,
    spare: u32,
    recipients: &[PublicKey],
) -> Result<(u32, SecretMeta), SyncError> {
    let current = v
        .session
        .stored(id)
        .cloned()
        .ok_or_else(|| SyncError::Protocol(format!("{id} vanished during sync")))?;
    let mut chain: Vec<StoredSecret> = v
        .store
        .history(id)?
        .into_iter()
        .filter(|h| h.secret.revision > after && h.secret.revision < current.secret.revision)
        .collect();
    chain.reverse();
    chain.push(current);
    let opened = chain
        .iter()
        .map(|stored| v.session.open_parts(stored))
        .collect::<Result<Vec<_>, _>>()?;

    let count = u32::try_from(opened.len()).ok();
    let newest = count
        .and_then(|n| base.checked_add(n))
        .filter(|n| n.checked_add(spare).is_some())
        .ok_or_else(|| SyncError::Protocol(format!("{id} has run out of revisions")))?;
    for old in &chain[..chain.len() - 1] {
        v.store.unarchive(id, old.secret.revision)?;
    }
    for (revision, (meta, body)) in (base + 1..=newest).zip(&opened) {
        // The first replaces the current revision, which is in `opened`
        // already; each later one moves the one before it into history.
        v.session.reseal_for(
            v.store,
            rng,
            id,
            revision,
            meta,
            body,
            revision > base + 1,
            recipients,
        )?;
    }
    let (meta, _) = opened
        .into_iter()
        .next_back()
        .expect("the chain ends with current");
    Ok((newest, meta))
}

fn apply_delete(
    v: &mut Vault<'_>,
    rng: &mut impl CryptoRng,
    tombstone: Tombstone,
    progress: &mut Progress,
) -> Result<(), SyncError> {
    let id = tombstone.secret_id;
    if v.session.is_local_only(id) {
        progress.report.skipped += 1;
        return Ok(());
    }
    if tombstone.verify(&v.session.owner(id).signing_key).is_err() {
        progress.report.skipped += 1;
        return Ok(());
    }
    v.state.deletes.remove(&id);
    v.state.deleted_remotely.remove(&id);
    let known = v.state.known.get(&id).copied();
    if known.is_some_and(|k| tombstone.revision < k) {
        progress.report.skipped += 1;
        return Ok(());
    }
    match v.session.stored(id).map(|s| s.secret.revision) {
        None => {
            v.state.known.remove(&id);
        }
        Some(local) if known == Some(local) || (known.is_none() && local <= tombstone.revision) => {
            v.session.remove_id(v.store, id)?;
            v.state.known.remove(&id);
            progress.report.removed += 1;
        }
        Some(_) => {
            if v.session.get(&id.to_string())?.meta.kind == silo_core::vault::SecretKind::File {
                let original = path(v, id);
                let (copy, _) = save_local_file_copy(v, rng, id, progress.now)?;
                record_conflict(
                    v,
                    progress,
                    format!(
                        "{original}: kept the server deletion; local file edits saved privately as {} (id {})",
                        copy.path(),
                        copy.id
                    ),
                )?;
                v.session.remove_id(v.store, id)?;
                v.state.known.remove(&id);
                progress.report.removed += 1;

                return Ok(());
            }
            // Changed here since: the edit wins and goes back up as a restore,
            // on top of the deleted revision.
            progress.gap(id, known, tombstone.revision.saturating_add(1));
            let after = known.unwrap_or(tombstone.revision);
            // A tombstone does not carry the latest grants. Restore privately
            // rather than resurrecting recipients from an obsolete revision.
            let owner = [*v.session.public_key()];
            rebase_local(v, rng, id, after, tombstone.revision, 0, &owner)?;
            v.state.deleted_remotely.insert(id, tombstone.revision);
            v.state.known.insert(id, tombstone.revision);
            record_conflict(
                v,
                progress,
                format!(
                    "{}: deleted on another device but changed here; kept yours",
                    path(v, id)
                ),
            )?;
        }
    }
    Ok(())
}

/// The next push: every pending deletion, and for each changed secret the
/// oldest revision the server does not have yet.
fn plan_push(v: &mut Vault<'_>) -> Result<Vec<PushItem>, SyncError> {
    let mut items: Vec<PushItem> = v
        .state
        .deletes
        .values()
        .map(|tombstone| PushItem::Delete {
            tombstone: tombstone.clone(),
        })
        .collect();
    for (id, current) in v.session.revisions() {
        if !v.session.is_syncable(id) {
            continue;
        }
        let known = v.state.known.get(&id).copied();
        if known == Some(current)
            || known.is_some_and(|k| current < k)
            || v.state
                .rejected
                .get(&id)
                .is_some_and(|r| r.revision == current)
        {
            continue;
        }
        let next = match known {
            // Revisions made here since the last one the server has, oldest first.
            Some(k) => v
                .store
                .history(id)?
                .into_iter()
                .filter(|h| h.secret.revision > k && h.secret.revision < current)
                .min_by_key(|h| h.secret.revision),
            // Never synced: only the current revision.
            None => None,
        };
        let next = match next {
            Some(next) => next,
            None => v
                .session
                .stored(id)
                .cloned()
                .expect("listed ids are stored"),
        };
        let entry = v.session.sign_if_needed(v.store, next)?;
        items.push(PushItem::Put {
            base_revision: known.unwrap_or(0),
            entry,
            restore: v.state.deleted_remotely.contains_key(&id),
        });
    }
    Ok(items)
}

/// Notes the revisions about to be sent, before sending them.
fn begin_push(v: &mut Vault<'_>, items: &[PushItem]) {
    for item in items {
        if let PushItem::Put { entry, .. } = item {
            v.state.in_flight.insert(entry.secret.id, digest_hex(entry));
        }
    }
}

fn apply_result(
    v: &mut Vault<'_>,
    rng: &mut impl CryptoRng,
    item: &PushItem,
    result: PushResult,
    progress: &mut Progress,
) -> Result<(), SyncError> {
    let id = item.secret_id();
    if matches!(item, PushItem::Put { .. }) {
        v.state.in_flight.remove(&id);
    }
    match (item, result) {
        (PushItem::Put { entry, .. }, PushResult::Ok { .. }) => {
            let revision = entry.secret.revision;
            v.state.deleted_remotely.remove(&id);
            v.state.rejected.remove(&id);
            progress.report.pushed += 1;
            if v.session.stored(id).is_some() {
                v.state.known.insert(id, revision);
            } else {
                // Deleted here while the upload was on its way: what the
                // server has now must go too, or the next pull brings it back.
                v.state.known.remove(&id);
                let tombstone = v.session.tombstone(id, revision, progress.now);
                v.state.deletes.insert(id, tombstone);
            }
        }
        (PushItem::Delete { .. }, PushResult::Ok { .. }) => {
            v.state.deletes.remove(&id);
            v.state.known.remove(&id);
            progress.report.pushed += 1;
        }
        (_, PushResult::Conflict { current }) => apply_change(v, rng, *current, progress)?,
        (PushItem::Put { .. }, PushResult::Rejected { message }) => {
            progress
                .report
                .rejected
                .push(format!("{}: {message}", path(v, id)));
            // Deleted here meanwhile: nothing left to hold back.
            if let Some(stored) = v.session.stored(id) {
                let revision = stored.secret.revision;
                v.state.rejected.insert(id, Rejection { revision, message });
            }
        }
        (PushItem::Delete { .. }, PushResult::Rejected { message }) => {
            v.state.deletes.remove(&id);
            v.state.known.remove(&id);
            progress
                .report
                .rejected
                .push(format!("deletion of {id}: {message}"));
        }
    }
    Ok(())
}

/// Records that a secret was deleted here, so the next sync deletes it on
/// the server too if the server has it.
pub fn record_deletion(state: &mut SyncState, session: &Session, id: SecretId, now: u64) {
    if !session.is_syncable(id) {
        return;
    }
    state.rejected.remove(&id);
    if state.deleted_remotely.remove(&id).is_some() {
        // Already deleted on the server; only the local edit was keeping it.
        state.known.remove(&id);
    } else if let Some(revision) = state.known.remove(&id) {
        state
            .deletes
            .insert(id, session.tombstone(id, revision, now));
    }
}

/// Identifies one sealed revision: two devices can both make a revision 2.
fn digest_hex(stored: &StoredSecret) -> String {
    stored
        .secret
        .digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn path(v: &Vault<'_>, id: SecretId) -> String {
    v.session.path_of(id).unwrap_or_else(|| id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;
    use crate::protocol::NewSecret;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use silo_core::AccountRecord;
    use silo_core::crypto::KdfParams;
    use silo_core::vault::{FolderPath, Note, SecretBody};

    struct Setup {
        _dir: tempfile::TempDir,
        store: Store,
        session: Session,
        state: SyncState,
        rng: StdRng,
    }

    impl Setup {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(Paths::new(dir.path())).unwrap();
            let mut rng = StdRng::seed_from_u64(7);
            let kdf = KdfParams::new(&mut rng, 256, 1, 1);
            let (record, _) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();
            store.write_account(&record).unwrap();
            let (session, _) = Session::unlock(&store, b"pw").unwrap();
            Self {
                _dir: dir,
                store,
                session,
                state: SyncState::default(),
                rng,
            }
        }

        fn add(&mut self) -> SecretId {
            let new = NewSecret {
                title: "new".into(),
                folder: FolderPath::default(),
                tags: vec![],
                urls: vec![],
                basic_auth: false,
                body: SecretBody::Note(Note { text: "x".into() }),
            };
            self.session
                .add(&self.store, &mut self.rng, 1, new)
                .unwrap()
                .id
        }

        fn vault(&mut self) -> (Vault<'_>, &mut StdRng) {
            (
                Vault {
                    store: &self.store,
                    session: &mut self.session,
                    state: &mut self.state,
                },
                &mut self.rng,
            )
        }
    }

    /// The one upload `plan_push` has for `id`.
    fn upload(v: &mut Vault<'_>, id: SecretId) -> (PushItem, StoredSecret) {
        let items = plan_push(v).unwrap();
        let item = items
            .into_iter()
            .find(|item| item.secret_id() == id)
            .unwrap();
        let PushItem::Put { entry, .. } = &item else {
            panic!("{item:?}")
        };
        let entry = entry.clone();
        (item, entry)
    }

    fn assert_deletes_on_next_push(v: &mut Vault<'_>, id: SecretId, revision: u32) {
        assert!(v.session.stored(id).is_none());
        assert!(!v.state.known.contains_key(&id));
        let items = plan_push(v).unwrap();
        assert!(
            matches!(&items[..], [PushItem::Delete { tombstone }]
                if tombstone.secret_id == id && tombstone.revision == revision),
            "{items:?}"
        );
    }

    #[test]
    fn a_deletion_during_an_upload_deletes_the_upload() {
        let mut setup = Setup::new();
        let id = setup.add();
        let (mut v, rng) = setup.vault();
        let mut progress = Progress::default();
        let (item, entry) = upload(&mut v, id);
        begin_push(&mut v, std::slice::from_ref(&item));
        // Removed while the push is on its way; never synced, so there is no
        // deletion to record.
        v.session.remove_id(v.store, id).unwrap();
        record_deletion(v.state, v.session, id, 5);
        let ok = PushResult::Ok { seq: 1 };
        apply_result(&mut v, rng, &item, ok, &mut progress).unwrap();
        // The upload coming back in a pull stays deleted.
        let change = Change::Put { seq: 1, entry };
        apply_change(&mut v, rng, change, &mut progress).unwrap();
        assert_deletes_on_next_push(&mut v, id, 1);
    }

    #[test]
    fn a_deletion_during_an_upload_whose_reply_is_lost_deletes_it() {
        // Also with a logout and login before the next sync.
        for relogin in [false, true] {
            let mut setup = Setup::new();
            let new = setup.add();
            let (mut v, rng) = setup.vault();
            let mut progress = Progress::default();

            // A first upload.
            let (item, entry) = upload(&mut v, new);
            begin_push(&mut v, std::slice::from_ref(&item));
            v.session.remove_id(v.store, new).unwrap();
            record_deletion(v.state, v.session, new, 5);
            // The reply never arrives; the next pull has the upload.
            if relogin {
                let baseline = v.state.baseline();
                *v.state = SyncState::default();
                assert!(v.state.resume(baseline));
            }
            let change = Change::Put { seq: 1, entry };
            apply_change(&mut v, rng, change, &mut progress).unwrap();
            assert_deletes_on_next_push(&mut v, new, 1);
        }
    }

    #[test]
    fn another_devices_edit_with_the_same_number_beats_the_deletion() {
        let mut setup = Setup::new();
        let id = setup.add();
        let (mut v, rng) = setup.vault();
        let mut progress = Progress::default();
        v.state.known.insert(id, 1);
        let current = v.session.stored(id).unwrap().clone();
        let (meta, body) = v.session.open_parts(&current).unwrap();
        v.session
            .reseal(v.store, rng, id, 2, &meta, &body, true)
            .unwrap();
        // Revision 2 from here goes out but never reaches the server…
        let (item, _) = upload(&mut v, id);
        begin_push(&mut v, std::slice::from_ref(&item));
        // …while another device makes its own revision 2.
        let theirs = v
            .session
            .reseal(v.store, rng, id, 2, &meta, &body, false)
            .unwrap();
        v.session.remove_id(v.store, id).unwrap();
        record_deletion(v.state, v.session, id, 5);

        let change = Change::Put {
            seq: 2,
            entry: theirs.clone(),
        };
        apply_change(&mut v, rng, change, &mut progress).unwrap();
        assert_eq!(progress.report.conflicts.len(), 1, "{:?}", progress.report);
        assert!(v.state.deletes.is_empty());
        assert_eq!(
            v.session.stored(id).unwrap().secret.digest(),
            theirs.secret.digest()
        );
        assert!(plan_push(&mut v).unwrap().is_empty());
    }

    #[test]
    fn a_deletion_during_an_edit_upload_whose_reply_is_lost_deletes_it() {
        let mut setup = Setup::new();
        let id = setup.add();
        let (mut v, rng) = setup.vault();
        let mut progress = Progress::default();
        v.state.known.insert(id, 1);
        let current = v.session.stored(id).unwrap().clone();
        let (meta, body) = v.session.open_parts(&current).unwrap();
        v.session
            .reseal(v.store, rng, id, 2, &meta, &body, true)
            .unwrap();

        let (item, entry) = upload(&mut v, id);
        begin_push(&mut v, std::slice::from_ref(&item));
        v.session.remove_id(v.store, id).unwrap();
        record_deletion(v.state, v.session, id, 5);
        assert_eq!(v.state.deletes[&id].revision, 1);
        let change = Change::Put { seq: 2, entry };
        apply_change(&mut v, rng, change, &mut progress).unwrap();
        assert_deletes_on_next_push(&mut v, id, 2);
    }

    #[test]
    fn an_own_revision_coming_back_is_not_a_conflict() {
        let mut setup = Setup::new();
        let id = setup.add();
        let (mut v, rng) = setup.vault();
        let mut progress = Progress::default();
        v.state.known.insert(id, 1);
        let current = v.session.stored(id).unwrap().clone();
        let (meta, body) = v.session.open_parts(&current).unwrap();
        v.session
            .reseal(v.store, rng, id, 2, &meta, &body, true)
            .unwrap();
        let (item, entry) = upload(&mut v, id);
        begin_push(&mut v, std::slice::from_ref(&item));
        // Edited again before the lost reply; revision 2 is in history now.
        v.session
            .reseal(v.store, rng, id, 3, &meta, &body, true)
            .unwrap();
        let change = Change::Put { seq: 2, entry };
        apply_change(&mut v, rng, change, &mut progress).unwrap();
        assert!(
            progress.report.conflicts.is_empty(),
            "{:?}",
            progress.report
        );
        assert_eq!(v.state.known[&id], 2);
        assert_eq!(v.session.stored(id).unwrap().secret.revision, 3);
    }
}
