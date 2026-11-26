//! Read-only pipeline credentials. Only a derived bearer goes over HTTP.
//! The local secret opens revision grants for the recipient, and the pinned
//! owner signing key authenticates both the scope and the returned revisions.
use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::account::AccountKeys;
use crate::crypto::{CryptoRng, PublicKey, SecretKey, Signature, SigningPublicKey};
use crate::vault::{EnvSet, Grant, SecretBody, SecretId, StoredSecret};
use crate::{Error, Result};

/// Printable form returned once to the owner. Debug output redacts the credential.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct IssuedToken(String);

impl IssuedToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuedToken(..)")
    }
}

pub struct AccessToken {
    secret: SecretKey,
    owner: SigningPublicKey,
}

impl AccessToken {
    pub fn generate(rng: &mut impl CryptoRng, owner: SigningPublicKey) -> Self {
        Self {
            secret: SecretKey::generate(rng),
            owner,
        }
    }

    pub fn encode(&self) -> IssuedToken {
        let mut bytes = Zeroizing::new([0; 64]);
        bytes[..32].copy_from_slice(self.secret.to_bytes().as_ref());
        bytes[32..].copy_from_slice(self.owner.as_bytes());
        let mut encoded = String::from("silo_env1_");
        URL_SAFE_NO_PAD.encode_string(bytes.as_slice(), &mut encoded);
        IssuedToken(encoded)
    }

    pub fn parse(input: &str) -> Result<Self> {
        let invalid = || Error::Decode("invalid Silo access token".into());
        let mut bytes = Zeroizing::new([0u8; 64]);
        let encoded = input.strip_prefix("silo_env1_").ok_or_else(invalid)?;
        if URL_SAFE_NO_PAD
            .decode_slice(encoded, bytes.as_mut())
            .map_err(|_| invalid())?
            != 64
        {
            return Err(invalid());
        }
        Ok(Self {
            secret: SecretKey::from_bytes(Zeroizing::new(bytes[..32].try_into().unwrap())),
            owner: SigningPublicKey::from_bytes(bytes[32..].try_into().unwrap()),
        })
    }

    pub fn recipient(&self) -> PublicKey {
        self.secret.public_key()
    }

    pub fn bearer(&self) -> Zeroizing<String> {
        let digest = Sha256::new()
            .chain_update(b"silo/v1/env-token/bearer")
            .chain_update(self.secret.to_bytes().as_ref())
            .finalize();
        Zeroizing::new(format!("silo_read_{}", URL_SAFE_NO_PAD.encode(digest)))
    }

    pub fn bearer_hash(&self) -> [u8; 32] {
        Sha256::digest(self.bearer().as_bytes()).into()
    }

    pub fn open(&self, bundle: TokenBundle) -> Result<EnvSet> {
        bundle.policy.verify(&self.owner)?;
        let recipient = self.recipient();
        if bundle.policy.recipient != recipient || bundle.entries.len() != bundle.policy.ids.len() {
            return Err(Error::NotRecipient);
        }
        let mut values = BTreeMap::new();
        for (id, entry) in bundle.policy.ids.iter().zip(bundle.entries) {
            let [grant] = entry.grants.as_slice() else {
                return Err(Error::NotRecipient);
            };
            if entry.secret.id != *id || grant.recipient != recipient {
                return Err(Error::NotRecipient);
            }
            entry.verify(&self.owner)?;
            let key = grant.open_for(&self.secret)?;
            let SecretBody::EnvSet(set) = &entry.secret.open_body(&key)? else {
                return Err(Error::Decode("token member is not an env set".into()));
            };
            for var in &set.vars {
                let mut name = var.key.bytes();
                if !name
                    .next()
                    .is_some_and(|c| c == b'_' || c.is_ascii_alphabetic())
                    || !name.all(|c| c == b'_' || c.is_ascii_alphanumeric())
                    || var.value.contains('\0')
                {
                    return Err(Error::Decode(
                        "invalid environment variable in token scope".into(),
                    ));
                }
                if values.insert(var.key.clone(), var.clone()).is_some() {
                    return Err(Error::Decode(format!(
                        "duplicate variable {} in token scope",
                        var.key
                    )));
                }
            }
        }
        Ok(EnvSet {
            vars: values.into_values().collect(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPolicy {
    pub name: String,
    pub recipient: PublicKey,
    pub ids: BTreeSet<SecretId>,
    pub signature: Signature,
}

fn digest(name: &str, recipient: PublicKey, ids: &BTreeSet<SecretId>) -> [u8; 32] {
    let mut hash = Sha256::new()
        .chain_update(b"silo/v1/env-token/scope")
        .chain_update((name.len() as u64).to_be_bytes())
        .chain_update(name)
        .chain_update(recipient.as_bytes());
    for id in ids {
        hash.update(id.as_bytes());
    }
    hash.finalize().into()
}

impl TokenPolicy {
    pub fn sign(
        owner: &AccountKeys,
        name: String,
        recipient: PublicKey,
        ids: BTreeSet<SecretId>,
    ) -> Result<Self> {
        let signature = owner.signing_key().sign(&digest(&name, recipient, &ids));
        let policy = Self {
            name,
            recipient,
            ids,
            signature,
        };
        policy.verify(&owner.identity().signing_key)?;
        Ok(policy)
    }

    pub fn verify(&self, signer: &SigningPublicKey) -> Result<()> {
        if self.name.is_empty()
            || self.name.len() > 128
            || !self
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        {
            return Err(Error::Decode(
                "use 1–128 letters, digits, hyphens or underscores for the token name".into(),
            ));
        }
        if self.ids.is_empty() {
            return Err(Error::Decode("token scope contains no env sets".into()));
        }
        self.signature
            .verify(signer, &digest(&self.name, self.recipient, &self.ids))
    }
}

#[derive(Serialize, Deserialize)]
pub struct InstallToken {
    pub policy: TokenPolicy,
    pub bearer_hash: [u8; 32],
    pub replaces: Option<PublicKey>,
    pub grants: Vec<Grant>,
}

#[derive(Serialize, Deserialize)]
pub struct TokenBundle {
    pub policy: TokenPolicy,
    /// Same order as the signed member IDs. Each entry carries only this recipient's grant.
    pub entries: Vec<StoredSecret>,
}

#[derive(Serialize, Deserialize)]
pub struct TokenState {
    pub policy: TokenPolicy,
    /// Current grant revision for each member.
    pub revisions: BTreeMap<SecretId, u32>,
}
