use core::fmt;

use ed25519_dalek::Signer;
use hkdf::Hkdf;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::bytes;
use super::keys::{KEY_LEN, SecretKey};
use crate::error::{Error, Result};

pub const SIGNATURE_LEN: usize = 64;

const SIGNING_KEY_INFO: &[u8] = b"silo/v1/signing-key";

/// Ed25519 key an account signs revisions, grants and tombstones with.
///
/// Derived from the account's X25519 secret key with HKDF, so it needs no
/// storage of its own and every existing account has one.
pub(crate) struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    pub(crate) fn derive(secret_key: &SecretKey) -> Self {
        let mut seed = Zeroizing::new([0u8; KEY_LEN]);
        Hkdf::<Sha256>::new(None, secret_key.to_bytes().as_ref())
            .expand(SIGNING_KEY_INFO, seed.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    pub(crate) fn public_key(&self) -> SigningPublicKey {
        SigningPublicKey(self.0.verifying_key().to_bytes())
    }

    /// Signs a 32-byte digest that already carries its own domain separation.
    pub(crate) fn sign(&self, digest: &[u8; 32]) -> Signature {
        Signature {
            signer: self.public_key(),
            bytes: self.0.sign(digest).to_bytes(),
        }
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

/// Ed25519 public key of an account. Safe to publish.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SigningPublicKey([u8; KEY_LEN]);

impl SigningPublicKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for SigningPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningPublicKey(")?;
        for b in &self.0[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..)")
    }
}

impl Serialize for SigningPublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        bytes::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for SigningPublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        bytes::deserialize_array(deserializer).map(Self)
    }
}

/// An Ed25519 signature together with the key that made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub signer: SigningPublicKey,
    #[serde(
        serialize_with = "bytes::serialize",
        deserialize_with = "bytes::deserialize_array"
    )]
    pub bytes: [u8; SIGNATURE_LEN],
}

impl Signature {
    /// Checks that `expected` signed `digest`. A signature by any other key,
    /// a malformed key, or a forged signature all fail with [`Error::BadSignature`].
    pub(crate) fn verify(&self, expected: &SigningPublicKey, digest: &[u8; 32]) -> Result<()> {
        if &self.signer != expected {
            return Err(Error::BadSignature);
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.signer.0)
            .map_err(|_| Error::BadSignature)?;
        key.verify_strict(digest, &ed25519_dalek::Signature::from_bytes(&self.bytes))
            .map_err(|_| Error::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn derivation_is_stable_and_per_account() {
        let mut rng = testing::rng(12);
        let a = SecretKey::generate(&mut rng);
        let b = SecretKey::generate(&mut rng);
        assert_eq!(
            SigningKey::derive(&a).public_key(),
            SigningKey::derive(&SecretKey::from_bytes(a.to_bytes())).public_key()
        );
        assert_ne!(
            SigningKey::derive(&a).public_key(),
            SigningKey::derive(&b).public_key()
        );
        // Not the X25519 public key reinterpreted.
        assert_ne!(
            SigningKey::derive(&a).public_key().as_bytes(),
            a.public_key().as_bytes()
        );
    }

    #[test]
    fn verify_checks_signer_digest_and_bytes() {
        let mut rng = testing::rng(13);
        let alice = SigningKey::derive(&SecretKey::generate(&mut rng));
        let bob = SigningKey::derive(&SecretKey::generate(&mut rng));
        let sig = alice.sign(&[1; 32]);

        assert_eq!(sig.verify(&alice.public_key(), &[1; 32]), Ok(()));
        assert_eq!(
            sig.verify(&alice.public_key(), &[2; 32]),
            Err(Error::BadSignature)
        );
        assert_eq!(
            sig.verify(&bob.public_key(), &[1; 32]),
            Err(Error::BadSignature)
        );

        let mut claimed = bob.sign(&[1; 32]);
        claimed.signer = alice.public_key();
        assert_eq!(
            claimed.verify(&alice.public_key(), &[1; 32]),
            Err(Error::BadSignature)
        );

        let mut flipped = sig.clone();
        flipped.bytes[0] ^= 1;
        assert_eq!(
            flipped.verify(&alice.public_key(), &[1; 32]),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn signature_json_is_base64() {
        let mut rng = testing::rng(14);
        let key = SigningKey::derive(&SecretKey::generate(&mut rng));
        let sig = key.sign(&[0; 32]);
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.starts_with(r#"{"signer":""#), "{json}");
        assert_eq!(serde_json::from_str::<Signature>(&json).unwrap(), sig);
    }
}
