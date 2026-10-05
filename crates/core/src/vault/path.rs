use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::{Error, Result};

/// Maximum nesting depth of a folder path.
pub const MAX_DEPTH: usize = 32;
/// Maximum length in bytes of one folder segment.
pub const MAX_SEGMENT_LEN: usize = 128;
/// Maximum length in bytes of a tag.
pub const MAX_TAG_LEN: usize = 64;

/// Nested folder location such as `projects/wallet`.
///
/// The root folder is the empty path. Segments are separated by `/`, must be
/// non-empty, trimmed, free of control characters, and may not be `.` or `..`
/// so hosts can safely mirror folders onto a filesystem.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FolderPath(Vec<String>);

impl FolderPath {
    pub const SEPARATOR: char = '/';

    /// The root folder.
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// Parses a path like `projects/wallet`. The empty string is the root.
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Ok(Self::root());
        }
        let segments = input
            .split(Self::SEPARATOR)
            .map(|segment| validate_segment(input, segment))
            .collect::<Result<Vec<_>>>()?;
        if segments.len() > MAX_DEPTH {
            return Err(Error::InvalidPath(input.to_owned(), "too deep"));
        }
        Ok(Self(segments))
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn depth(&self) -> usize {
        self.0.len()
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// Last segment, or `None` for the root.
    pub fn name(&self) -> Option<&str> {
        self.0.last().map(String::as_str)
    }

    /// Enclosing folder, or `None` for the root.
    pub fn parent(&self) -> Option<Self> {
        let (_, parents) = self.0.split_last()?;
        Some(Self(parents.to_vec()))
    }

    /// Appends one segment.
    pub fn join(&self, segment: &str) -> Result<Self> {
        let mut segments = self.0.clone();
        segments.push(validate_segment(segment, segment)?);
        if segments.len() > MAX_DEPTH {
            return Err(Error::InvalidPath(segment.to_owned(), "too deep"));
        }
        Ok(Self(segments))
    }

    /// True when `self` is `ancestor` itself or lies somewhere beneath it.
    pub fn starts_with(&self, ancestor: &Self) -> bool {
        self.0.starts_with(&ancestor.0)
    }
}

fn validate_segment(full: &str, segment: &str) -> Result<String> {
    let invalid = |reason| Error::InvalidPath(full.to_owned(), reason);
    if segment.is_empty() {
        return Err(invalid("empty segment"));
    }
    if segment.len() > MAX_SEGMENT_LEN {
        return Err(invalid("segment too long"));
    }
    if segment != segment.trim() {
        return Err(invalid("segment has leading or trailing whitespace"));
    }
    if segment.chars().any(char::is_control) {
        return Err(invalid("segment contains control characters"));
    }
    if segment.contains(FolderPath::SEPARATOR) {
        return Err(invalid("segment contains a separator"));
    }
    if segment == "." || segment == ".." {
        return Err(invalid("segment must not be . or .."));
    }
    Ok(segment.to_owned())
}

impl fmt::Display for FolderPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, segment) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("/")?;
            }
            f.write_str(segment)?;
        }
        Ok(())
    }
}

impl FromStr for FolderPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for FolderPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for FolderPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

/// Free-form label attached to a secret.
///
/// Trimmed, non-empty, at most [`MAX_TAG_LEN`] bytes, no control characters
/// and no commas (so `a,b,c` on a command line is unambiguous).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tag(String);

impl Tag {
    pub fn new(input: &str) -> Result<Self> {
        let invalid = |reason| Error::InvalidTag(input.to_owned(), reason);
        if input.is_empty() {
            return Err(invalid("empty"));
        }
        if input.len() > MAX_TAG_LEN {
            return Err(invalid("too long"));
        }
        if input != input.trim() {
            return Err(invalid("leading or trailing whitespace"));
        }
        if input.chars().any(char::is_control) {
            return Err(invalid("contains control characters"));
        }
        if input.contains(',') {
            return Err(invalid("contains a comma"));
        }
        Ok(Self(input.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Tag {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl Serialize for Tag {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Tag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_paths() {
        let path = FolderPath::parse("projects/wallet").unwrap();
        assert_eq!(path.depth(), 2);
        assert_eq!(path.name(), Some("wallet"));
        assert_eq!(path.to_string(), "projects/wallet");
        assert_eq!(path.parent().unwrap().to_string(), "projects");
        assert_eq!(path.parent().unwrap().parent(), Some(FolderPath::root()));
        assert_eq!(FolderPath::root().parent(), None);
    }

    #[test]
    fn empty_string_is_root() {
        let root = FolderPath::parse("").unwrap();
        assert!(root.is_root());
        assert_eq!(root.to_string(), "");
        assert_eq!(root, FolderPath::default());
    }

    #[test]
    fn rejects_bad_segments() {
        for bad in [
            "/projects",
            "projects/",
            "projects//wallet",
            " projects",
            "projects /wallet",
            "a/./b",
            "a/../b",
            "tab\there",
        ] {
            assert!(
                matches!(FolderPath::parse(bad), Err(Error::InvalidPath(..))),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_excess_depth() {
        let deep = vec!["x"; MAX_DEPTH + 1].join("/");
        assert!(FolderPath::parse(&deep).is_err());
        let ok = vec!["x"; MAX_DEPTH].join("/");
        assert!(FolderPath::parse(&ok).is_ok());
    }

    #[test]
    fn join_and_starts_with() {
        let projects = FolderPath::parse("projects").unwrap();
        let wallet = projects.join("wallet").unwrap();
        assert_eq!(wallet.to_string(), "projects/wallet");
        assert!(wallet.starts_with(&projects));
        assert!(wallet.starts_with(&wallet));
        assert!(wallet.starts_with(&FolderPath::root()));
        assert!(!projects.starts_with(&wallet));
        assert!(projects.join("a/b").is_err());
    }

    #[test]
    fn path_serde_roundtrip_as_string() {
        let path = FolderPath::parse("projects/wallet").unwrap();
        let json = serde_json::to_string(&path).unwrap();
        assert_eq!(json, "\"projects/wallet\"");
        let back: FolderPath = serde_json::from_str(&json).unwrap();
        assert_eq!(back, path);
        assert!(serde_json::from_str::<FolderPath>("\"/bad\"").is_err());
    }

    #[test]
    fn tags() {
        assert_eq!(Tag::new("prod").unwrap().as_str(), "prod");
        assert_eq!(
            Tag::new("needs review").unwrap().to_string(),
            "needs review"
        );
        for bad in [
            "",
            " prod",
            "prod ",
            "a,b",
            "x\n",
            &"t".repeat(MAX_TAG_LEN + 1),
        ] {
            assert!(
                matches!(Tag::new(bad), Err(Error::InvalidTag(..))),
                "{bad:?}"
            );
        }
        let json = serde_json::to_string(&Tag::new("prod").unwrap()).unwrap();
        assert_eq!(json, "\"prod\"");
        assert!(serde_json::from_str::<Tag>("\"a,b\"").is_err());
    }
}
