use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use super::bytes;
use crate::crypto::CryptoRng;
use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

/// 192-bit XChaCha20 nonce. Large enough to draw at random for every message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut bytes = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl Serialize for Nonce {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        bytes::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        bytes::deserialize_array(deserializer).map(Self)
    }
}

/// XChaCha20-Poly1305 output: nonce plus ciphertext with its 16-byte tag.
///
/// The associated data is *not* stored. Callers reconstruct it from context
/// (secret id, revision, part, recipient), which is what binds a blob to its place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub nonce: Nonce,
    #[serde(
        serialize_with = "bytes::serialize",
        deserialize_with = "bytes::deserialize_vec"
    )]
    pub data: Vec<u8>,
}

pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    rng: &mut impl CryptoRng,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Ciphertext> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let nonce = Nonce::generate(rng);
    let data = cipher
        .encrypt(
            &XNonce::from(nonce.0),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Encode("aead encryption failed".to_owned()))?;
    Ok(Ciphertext { nonce, data })
}

pub(crate) fn open(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    ciphertext: &Ciphertext,
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt(
            &XNonce::from(ciphertext.nonce.0),
            Payload {
                msg: &ciphertext.data,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn roundtrip_and_tamper_detection() {
        let mut rng = testing::rng(1);
        let key = [7u8; KEY_LEN];
        let sealed = seal(&key, &mut rng, b"ctx", b"hello").unwrap();
        assert_eq!(sealed.data.len(), 5 + 16);
        assert_eq!(open(&key, b"ctx", &sealed).unwrap().as_slice(), b"hello");

        assert_eq!(open(&key, b"other", &sealed), Err(Error::Decrypt));
        assert_eq!(open(&[8u8; KEY_LEN], b"ctx", &sealed), Err(Error::Decrypt));

        let mut tampered = sealed.clone();
        tampered.data[0] ^= 1;
        assert_eq!(open(&key, b"ctx", &tampered), Err(Error::Decrypt));
    }

    #[test]
    fn fresh_nonce_every_time() {
        let mut rng = testing::rng(2);
        let key = [1u8; KEY_LEN];
        let a = seal(&key, &mut rng, b"", b"x").unwrap();
        let b = seal(&key, &mut rng, b"", b"x").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.data, b.data);
    }

    #[test]
    fn ciphertext_json_is_base64() {
        let ct = Ciphertext {
            nonce: Nonce([0; NONCE_LEN]),
            data: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&ct).unwrap();
        assert_eq!(
            json,
            r#"{"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","data":"AQID"}"#
        );
        assert_eq!(serde_json::from_str::<Ciphertext>(&json).unwrap(), ct);
    }
}
