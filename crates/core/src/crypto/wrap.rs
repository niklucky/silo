use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::aead::{self, Ciphertext};
use super::keys::{DataKey, PublicKey, SecretKey};
use crate::crypto::CryptoRng;
use crate::error::{Error, Result};

const WRAP_INFO: &[u8] = b"secret/v1/key-wrap";

/// A [`DataKey`] encrypted to one recipient's public key.
///
/// Construction: fresh ephemeral X25519 keypair, Diffie-Hellman with the
/// recipient, HKDF-SHA256 over the shared secret with both public keys as salt,
/// then XChaCha20-Poly1305 over the data key with caller-supplied associated data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    pub ephemeral: PublicKey,
    pub ciphertext: Ciphertext,
}

impl WrappedKey {
    pub(crate) fn seal(
        rng: &mut impl CryptoRng,
        key: &DataKey,
        recipient: &PublicKey,
        aad: &[u8],
    ) -> Result<Self> {
        let ephemeral = SecretKey::generate(rng);
        let ephemeral_public = ephemeral.public_key();
        let shared = ephemeral
            .diffie_hellman(recipient)
            .ok_or_else(|| Error::Encode("recipient public key is a low-order point".to_owned()))?;
        let wrap_key = derive_wrap_key(&shared, &ephemeral_public, recipient);
        let ciphertext = aead::seal(&wrap_key, rng, aad, key.as_bytes())?;
        Ok(Self {
            ephemeral: ephemeral_public,
            ciphertext,
        })
    }

    pub(crate) fn open(&self, recipient: &SecretKey, aad: &[u8]) -> Result<DataKey> {
        let shared = recipient
            .diffie_hellman(&self.ephemeral)
            .ok_or(Error::Decrypt)?;
        let wrap_key = derive_wrap_key(&shared, &self.ephemeral, &recipient.public_key());
        let plain = aead::open(&wrap_key, aad, &self.ciphertext)?;
        let mut bytes = Zeroizing::new([0u8; aead::KEY_LEN]);
        if plain.len() != bytes.len() {
            return Err(Error::Decrypt);
        }
        bytes.copy_from_slice(&plain);
        Ok(DataKey::from_bytes(bytes))
    }
}

fn derive_wrap_key(
    shared: &[u8; 32],
    ephemeral: &PublicKey,
    recipient: &PublicKey,
) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral.as_bytes());
    salt[32..].copy_from_slice(recipient.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(WRAP_INFO, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn only_the_recipient_can_unwrap() {
        let mut rng = testing::rng(9);
        let key = DataKey::generate(&mut rng);
        let bob = SecretKey::generate(&mut rng);
        let eve = SecretKey::generate(&mut rng);

        let wrapped = WrappedKey::seal(&mut rng, &key, &bob.public_key(), b"ctx").unwrap();
        assert_eq!(
            wrapped.open(&bob, b"ctx").unwrap().as_bytes(),
            key.as_bytes()
        );
        assert_eq!(wrapped.open(&eve, b"ctx").unwrap_err(), Error::Decrypt);
        assert_eq!(wrapped.open(&bob, b"other").unwrap_err(), Error::Decrypt);
    }

    #[test]
    fn each_wrap_uses_a_fresh_ephemeral_key() {
        let mut rng = testing::rng(10);
        let key = DataKey::generate(&mut rng);
        let bob = SecretKey::generate(&mut rng).public_key();
        let a = WrappedKey::seal(&mut rng, &key, &bob, b"").unwrap();
        let b = WrappedKey::seal(&mut rng, &key, &bob, b"").unwrap();
        assert_ne!(a.ephemeral, b.ephemeral);
    }

    #[test]
    fn rejects_low_order_recipient() {
        let mut rng = testing::rng(11);
        let key = DataKey::generate(&mut rng);
        let bad = PublicKey::from_bytes([0; 32]);
        assert!(matches!(
            WrappedKey::seal(&mut rng, &key, &bad, b""),
            Err(Error::Encode(_))
        ));
    }
}
