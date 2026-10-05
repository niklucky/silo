//! Serde helpers for byte strings: base64 in human-readable formats (JSON),
//! raw bytes in binary formats (CBOR).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Deserializer, Serializer, de};

pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(&BASE64.encode(bytes))
    } else {
        serializer.serialize_bytes(bytes)
    }
}

pub fn deserialize_vec<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    if deserializer.is_human_readable() {
        let text = String::deserialize(deserializer)?;
        BASE64.decode(text).map_err(de::Error::custom)
    } else {
        serde_bytes::ByteBuf::deserialize(deserializer).map(serde_bytes::ByteBuf::into_vec)
    }
}

pub fn deserialize_array<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let bytes = deserialize_vec(deserializer)?;
    let len = bytes.len();
    <[u8; N]>::try_from(bytes).map_err(|_| {
        let expected = format!("{N} bytes");
        de::Error::invalid_length(len, &expected.as_str())
    })
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Holder {
        #[serde(
            serialize_with = "super::serialize",
            deserialize_with = "super::deserialize_array"
        )]
        fixed: [u8; 4],
        #[serde(
            serialize_with = "super::serialize",
            deserialize_with = "super::deserialize_vec"
        )]
        dynamic: Vec<u8>,
    }

    #[test]
    fn json_uses_base64_and_cbor_uses_raw_bytes() {
        let value = Holder {
            fixed: [1, 2, 3, 4],
            dynamic: vec![0xFF; 3],
        };

        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, r#"{"fixed":"AQIDBA==","dynamic":"////"}"#);
        assert_eq!(serde_json::from_str::<Holder>(&json).unwrap(), value);

        let mut cbor = Vec::new();
        ciborium::into_writer(&value, &mut cbor).unwrap();
        assert!(cbor.len() < json.len());
        assert_eq!(
            ciborium::from_reader::<Holder, _>(cbor.as_slice()).unwrap(),
            value
        );
    }

    #[test]
    fn wrong_length_is_rejected() {
        let err = serde_json::from_str::<Holder>(r#"{"fixed":"AQID","dynamic":""}"#).unwrap_err();
        assert!(err.to_string().contains("4 bytes"), "{err}");
    }
}
