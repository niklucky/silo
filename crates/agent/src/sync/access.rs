use std::collections::BTreeSet;

use silo_core::access::{AccessToken, InstallToken, TokenPolicy};
use silo_core::vault::{SecretId, SecretKind};

use super::{HttpClient, SyncError, VaultAccess};
use crate::Session;
use crate::protocol::{ListFilter, Reply, TokenAction, TokenScope};

pub(super) fn refresh(access: &impl VaultAccess, client: &HttpClient) -> Result<(), SyncError> {
    for state in client.env_tokens()? {
        let grants = access.with_vault(|v| {
            let policy = &state.policy;
            // The server cannot choose a new recipient or add an ID to a signed scope.
            policy.verify(&v.session.identity().signing_key)?;
            let mut grants = Vec::new();
            for id in &policy.ids {
                if let Some(entry) = v.session.stored(*id)
                    && v.state.known.get(id) == Some(&entry.secret.revision)
                    && state.revisions.get(id) != Some(&entry.secret.revision)
                {
                    grants.push(v.session.env_grant(*id, policy.recipient)?);
                }
            }
            Ok(grants)
        })?;
        if !grants.is_empty() {
            client.refresh_env_grants(&grants)?;
        }
    }
    Ok(())
}

/// Folder selection always uses the current local env-set IDs, including descendants.
fn members(session: &Session, scope: TokenScope) -> Result<BTreeSet<SecretId>, SyncError> {
    Ok(match scope {
        TokenScope::EnvSet(selector) => BTreeSet::from([session.resolve(&selector)?]),
        TokenScope::Folder(folder) => session
            .list(&ListFilter {
                folder: Some(folder),
                kind: Some(SecretKind::EnvSet),
                ..Default::default()
            })
            .into_iter()
            .map(|item| item.id)
            .collect(),
    })
}

pub(crate) fn manage(access: &impl VaultAccess, action: TokenAction) -> Result<Reply, SyncError> {
    let client =
        access.with_vault(|v| Ok(HttpClient::new(&v.state.server)?.with_token(&v.state.token)))?;
    if matches!(
        action,
        TokenAction::Create { .. } | TokenAction::Rotate { .. }
    ) {
        super::run(access, &crate::unix_now)?;
    }
    let states = client.env_tokens()?;
    let policies = access.with_vault(|v| {
        let mut policies = Vec::new();
        for state in states {
            state.policy.verify(&v.session.identity().signing_key)?;
            policies.push(state.policy);
        }
        Ok(policies)
    })?;
    let find = |name: &str| {
        policies
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| SyncError::Config("unknown access token".into()))
    };
    match action {
        TokenAction::List | TokenAction::ListFor { .. } => access.with_vault(|v| {
            let selected = match action {
                TokenAction::ListFor { scope } => Some(members(v.session, scope)?),
                _ => None,
            };
            Ok(Reply::Tokens(
                policies
                    .into_iter()
                    .filter(|policy| {
                        selected
                            .as_ref()
                            .is_none_or(|ids| !ids.is_disjoint(&policy.ids))
                    })
                    .map(|policy| {
                        let paths = policy
                            .ids
                            .into_iter()
                            .map(|id| v.session.path_of(id).unwrap_or_else(|| id.to_string()))
                            .collect();
                        (policy.name, paths)
                    })
                    .collect(),
            ))
        }),
        TokenAction::Revoke { name } => {
            client.revoke_env_token(find(&name)?)?;
            Ok(Reply::TokenRevoked)
        }
        TokenAction::Create { name, scope } => {
            let ids = access.with_vault(|v| members(v.session, scope))?;
            issue(access, &client, name, ids, None)
        }
        TokenAction::Rotate { name } => {
            let old = find(&name)?;
            issue(access, &client, name, old.ids.clone(), Some(old))
        }
    }
}

fn issue(
    access: &impl VaultAccess,
    client: &HttpClient,
    name: String,
    ids: BTreeSet<SecretId>,
    replaces: Option<&TokenPolicy>,
) -> Result<Reply, SyncError> {
    let (request, credential) = access.with_vault(|v| {
        let token = AccessToken::generate(&mut rand::rng(), v.session.identity().signing_key);
        let policy = v.session.token_policy(name, token.recipient(), ids)?;
        let grants = policy
            .ids
            .iter()
            .map(|id| v.session.env_grant(*id, policy.recipient))
            .collect::<Result<_, _>>()?;
        Ok((
            InstallToken {
                policy,
                bearer_hash: token.bearer_hash(),
                replaces: replaces.map(|p| p.recipient),
                grants,
            },
            token.encode(),
        ))
    })?;
    client.install_env_token(&request)?;
    Ok(Reply::TokenIssued(credential))
}
