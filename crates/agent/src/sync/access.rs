use std::collections::{BTreeMap, BTreeSet};

use silo_core::access::{AccessToken, InstallToken, TokenPolicy};
use silo_core::crypto::PublicKey;
use silo_core::vault::{SecretId, SecretKind};

use super::{HttpClient, SyncError, VaultAccess};
use crate::Session;
use crate::protocol::{ListFilter, Reply, TokenAction, TokenScope};

pub(super) fn recipients(
    access: &impl VaultAccess,
    client: &HttpClient,
) -> Result<BTreeMap<SecretId, Vec<PublicKey>>, SyncError> {
    let states = client.env_tokens()?;
    access.with_vault(|v| {
        let mut members = BTreeMap::<_, Vec<_>>::new();
        for state in states {
            state.policy.verify(&v.session.identity().signing_key)?;
            for id in state.policy.ids {
                members.entry(id).or_default().push(state.policy.recipient);
            }
        }
        Ok(members)
    })
}

pub(super) fn refresh(
    access: &impl VaultAccess,
    client: &HttpClient,
) -> Result<Vec<String>, SyncError> {
    let mut warnings = Vec::new();
    for state in client.env_tokens()? {
        let grants = access.with_vault(|v| {
            let policy = &state.policy;
            // The server cannot choose a new recipient or add an ID to a signed scope.
            policy.verify(&v.session.identity().signing_key)?;
            if let Err(err) = v.session.validate_token_env(&policy.ids) {
                warnings.push(format!("{}: {err}", policy.name));
            }
            let mut grants = Vec::new();
            for id in &policy.ids {
                if let Some(entry) = v.session.stored(*id)
                    && v.state.known.get(id) == Some(&entry.secret.revision)
                    && state.revisions.get(id).copied().unwrap_or(0) < entry.secret.revision
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
    Ok(warnings)
}

/// Folder selection always uses the current local env-set IDs, including descendants.
fn members(session: &Session, scope: TokenScope) -> Result<BTreeSet<SecretId>, SyncError> {
    let (folder, preview) = match scope {
        TokenScope::EnvSet(selector) => return Ok(BTreeSet::from([session.resolve(&selector)?])),
        TokenScope::Folder(folder) => (folder, None),
        TokenScope::FolderSnapshot { folder, ids } => (folder, Some(ids)),
    };
    let members = session
        .list(&ListFilter {
            folder: Some(folder),
            kind: Some(SecretKind::EnvSet),
            ..Default::default()
        })
        .into_iter()
        .map(|item| item.id)
        .collect();
    if preview.is_some_and(|ids| ids != members) {
        return Err(SyncError::Config(
            "Folder membership changed. Review the updated env sets and issue the token again."
                .into(),
        ));
    }
    Ok(members)
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
        v.session.validate_token_env(&ids)?;
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
