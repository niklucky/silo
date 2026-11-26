//! Owner-only token management and a separate read-only redemption endpoint.
//! The server stores signed grants and a bearer hash. The token's decryption
//! key never reaches the server.
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{
        HeaderMap,
        header::{AUTHORIZATION, CACHE_CONTROL},
    },
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use rusqlite::{Connection, OptionalExtension, params};
use silo_core::access::{InstallToken, TokenBundle, TokenPolicy, TokenState};
use silo_core::sync::ErrorCode;
use silo_core::vault::{Grant, SealedSecret, StoredSecret};

use crate::AppState;
use crate::auth::{Account, Auth, sha256};
use crate::error::{ApiError, ApiResult};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/env-tokens", get(list).post(install))
        .route("/env-tokens/{name}", delete(revoke))
        .route("/env-token-grants", post(refresh))
        .route("/env", get(redeem))
}

async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<TokenState>>> {
    state
        .db
        .run(move |conn| {
            let mut stmt =
                conn.prepare("SELECT policy FROM env_tokens WHERE owner_id=? ORDER BY name")?;
            let mut revisions =
                conn.prepare("SELECT secret_id, revision FROM env_token_grants WHERE recipient=?")?;
            stmt.query_map([auth.account.id], |r| r.get::<_, String>(0))?
                .map(|row| {
                    let policy: TokenPolicy = serde_json::from_str(&row?)?;
                    let grants = revisions.query_map([policy.recipient.as_bytes()], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?))
                    })?;
                    let mut revisions = std::collections::BTreeMap::new();
                    for grant in grants {
                        let (id, revision) = grant?;
                        revisions.insert(id.parse().map_err(ApiError::internal)?, revision);
                    }
                    Ok(TokenState { policy, revisions })
                })
                .collect()
        })
        .await
        .map(Json)
}

fn policy_by_name(conn: &Connection, owner: i64, name: &str) -> ApiResult<Option<TokenPolicy>> {
    let row: Option<String> = conn
        .query_row(
            "SELECT policy FROM env_tokens WHERE owner_id=? AND name=?",
            params![owner, name],
            |r| r.get(0),
        )
        .optional()?;
    row.map(|json| serde_json::from_str(&json).map_err(Into::into))
        .transpose()
}

async fn install(
    State(state): State<AppState>,
    auth: Auth,
    Json(request): Json<InstallToken>,
) -> ApiResult<Json<()>> {
    state
        .db
        .run(move |conn| install_token(conn, &auth.account, request))
        .await
        .map(Json)
}

fn install_token(conn: &mut Connection, owner: &Account, request: InstallToken) -> ApiResult<()> {
    let tx = conn.transaction()?;
    let policy = request.policy;
    policy
        .verify(&owner.signing_key)
        .map_err(|err| ApiError::invalid(err.to_string()))?;
    let old = policy_by_name(&tx, owner.id, &policy.name)?;
    if old.as_ref().map(|p| p.recipient) != request.replaces {
        return Err(ApiError::invalid("token already exists or has changed"));
    }
    if let Some(old) = old {
        if old.ids != policy.ids || old.recipient == policy.recipient {
            return Err(ApiError::invalid(
                "rotation requires the same scope and a fresh key",
            ));
        }
        tx.execute(
            "DELETE FROM env_tokens WHERE recipient=?",
            [old.recipient.as_bytes()],
        )?;
    }
    tx.execute(
        "INSERT INTO env_tokens(owner_id,name,recipient,bearer_hash,policy) VALUES (?,?,?,?,?)",
        params![
            owner.id,
            policy.name,
            policy.recipient.as_bytes(),
            request.bearer_hash,
            serde_json::to_string(&policy)?
        ],
    )?;
    if !policy
        .ids
        .iter()
        .copied()
        .eq(request.grants.iter().map(|g| g.secret_id))
    {
        return Err(ApiError::invalid(
            "expected one ordered grant per scope member",
        ));
    }
    for grant in request.grants {
        save_grant(&tx, owner, &policy, &grant)?;
    }
    tx.commit()?;
    Ok(())
}

fn save_grant(
    conn: &Connection,
    owner: &Account,
    policy: &TokenPolicy,
    grant: &Grant,
) -> ApiResult<()> {
    if grant.recipient != policy.recipient || !policy.ids.contains(&grant.secret_id) {
        return Err(ApiError::invalid("grant is outside token scope"));
    }
    let id = grant.secret_id.to_string();
    let json: String = conn.query_row(
        "SELECT r.data FROM secrets s JOIN revisions r ON r.secret_id=s.id AND r.revision=s.current_revision
         WHERE s.id=? AND s.owner_id=? AND s.current_revision=? AND s.tombstone IS NULL",
        params![id, owner.id, grant.revision], |r| r.get(0)).optional()?
        .ok_or_else(|| ApiError::invalid("env set changed or is missing; sync and retry"))?;
    let secret: SealedSecret = serde_json::from_str(&json)?;
    grant
        .verify(&secret, &owner.signing_key)
        .map_err(|_| ApiError::invalid("invalid grant signature"))?;
    conn.execute("INSERT INTO env_token_grants(recipient,secret_id,revision,data) VALUES (?,?,?,?)
        ON CONFLICT(recipient,secret_id) DO UPDATE SET revision=excluded.revision,data=excluded.data",
        params![grant.recipient.as_bytes(),id,grant.revision,serde_json::to_string(grant)?])?;
    Ok(())
}

async fn refresh(
    State(state): State<AppState>,
    auth: Auth,
    Json(grants): Json<Vec<Grant>>,
) -> ApiResult<Json<()>> {
    state
        .db
        .run(move |conn| {
            let tx = conn.transaction()?;
            for grant in grants {
                let row: Option<String> = tx
                    .query_row(
                        "SELECT policy FROM env_tokens WHERE owner_id=? AND recipient=?",
                        params![auth.account.id, grant.recipient.as_bytes()],
                        |r| r.get(0),
                    )
                    .optional()?;
                // Another device can revoke or rotate while this update is on its way.
                if let Some(json) = row {
                    save_grant(&tx, &auth.account, &serde_json::from_str(&json)?, &grant)?;
                }
            }
            tx.commit()?;
            Ok(Json(()))
        })
        .await
}

async fn revoke(
    State(state): State<AppState>,
    auth: Auth,
    Path(name): Path<String>,
) -> ApiResult<Json<()>> {
    state
        .db
        .run(move |conn| {
            if conn.execute(
                "DELETE FROM env_tokens WHERE owner_id=? AND name=?",
                params![auth.account.id, name],
            )? == 0
            {
                return Err(ApiError::not_found("unknown access token"));
            }
            Ok(Json(()))
        })
        .await
}

async fn redeem(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let bearer = headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .filter(|s| s.starts_with("silo_read_"))
        .ok_or_else(denied)?;
    let hash = sha256(bearer.as_bytes());
    let bundle = state
        .db
        .run(move |conn| {
            let tx = conn.transaction()?;
            let bundle = current_bundle(&tx, &hash)?;
            tx.commit()?;
            Ok(bundle)
        })
        .await?;
    Ok(([(CACHE_CONTROL, "no-store")], Json(bundle)).into_response())
}

fn current_bundle(conn: &Connection, hash: &[u8; 32]) -> ApiResult<TokenBundle> {
    let (owner, json): (i64, String) = conn
        .query_row(
            "SELECT owner_id,policy FROM env_tokens WHERE bearer_hash=?",
            [hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or_else(denied)?;
    let policy: TokenPolicy = serde_json::from_str(&json)?;
    let mut stmt = conn.prepare(
        "SELECT r.data,g.data FROM env_token_grants g
         JOIN secrets s ON s.id=g.secret_id AND s.current_revision=g.revision
         JOIN revisions r ON r.secret_id=g.secret_id AND r.revision=g.revision
         WHERE g.recipient=? AND s.owner_id=? AND s.tombstone IS NULL ORDER BY s.id",
    )?;
    let rows = stmt.query_map(params![policy.recipient.as_bytes(), owner], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut entries = Vec::new();
    for row in rows {
        let (secret, grant) = row?;
        entries.push(StoredSecret {
            secret: serde_json::from_str(&secret)?,
            grants: vec![serde_json::from_str(&grant)?],
        });
    }
    if entries.len() != policy.ids.len() {
        return Err(ApiError::invalid(
            "token scope is incomplete; sync the owner vault or replace the token if a member was deleted",
        ));
    }
    Ok(TokenBundle { policy, entries })
}

fn denied() -> ApiError {
    ApiError::new(ErrorCode::Unauthorized, "unknown or revoked access token")
}
