//! Tag-value list parsing and serialisation.
//!
//! DKIM-Signature and DKIM DNS TXT records use a semicolon-separated list of
//! `tag=value` pairs (RFC 6376 §3.2). The grammar is:
//!
//! ```text
//! tag-list  = tag-spec *( ";" tag-spec ) [ ";" ]
//! tag-spec  = [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]
//! tag-name  = ALPHA *( ALPHA / DIGIT )
//! tag-value = [ tval *( 1*(WSP / FWS) tval ) ]   ; SP and HTAB allowed
//! tval      = 1*VALCHAR
//! VALCHAR   = %x21-3A / %x3C-7E   ; printable except ";"
//! ```
//!
//! Key properties:
//! - Whitespace (including FWS) around `=` and `;` is insignificant and MUST
//!   be ignored on parsing.
//! - Unknown tags MUST be ignored (RFC 6376 §3.2, rule 3). This enables
//!   forward compatibility.
//! - Duplicate tag names are not permitted; if encountered the signature MUST
//!   be treated as a `permerror` (RFC 6376 §3.2, rule 5).
//! - Ordering of tags is significant only for `b=`: when computing the
//!   signed hash of the DKIM-Signature header itself, `b=` is included with
//!   an empty value, and the byte positions of other tags are fixed by their
//!   original order in the header.

use std::collections::HashSet;

use crate::{Error, Result};

/// A parsed tag-value list.
///
/// Preserves insertion order for serialisation fidelity, while also allowing
/// O(1) lookup by tag name.
#[derive(Debug, Clone, Default)]
pub struct TagList {
    /// Tags in the order they appeared in the input.
    ordered: Vec<(String, String)>,
}

impl TagList {
    /// Parse a tag-value list string.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::TagListParse`] on syntax errors.
    /// Returns [`crate::Error::InvalidTag`] with `tag = "duplicate"` if a tag name
    /// appears more than once (RFC 6376 §3.2 rule 5).
    pub fn parse(input: &str) -> Result<Self> {
        let mut ordered = Vec::new();
        let mut seen = HashSet::new();

        for part in input.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let eq = part
                .find('=')
                .ok_or_else(|| Error::TagListParse(format!("missing '=' in tag spec: {part:?}")))?;
            let name = part[..eq].trim();
            let value = part[eq + 1..].trim();

            // RFC 6376 §3.2: tag-name = ALPHA *( ALPHA / DIGIT )
            let mut chars = name.chars();
            let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                && chars.all(|c| c.is_ascii_alphanumeric());
            if !valid {
                return Err(Error::TagListParse(format!("invalid tag name: {name:?}")));
            }

            // RFC 6376 §3.2 rule 5: duplicate tag names are a permerror
            if !seen.insert(name.to_owned()) {
                return Err(Error::InvalidTag {
                    tag: "duplicate",
                    reason: format!("tag {name:?} appears more than once"),
                });
            }

            ordered.push((name.to_owned(), value.to_owned()));
        }

        Ok(Self { ordered })
    }

    /// Retrieve the value of a tag by name, or `None` if absent.
    ///
    /// The name comparison is case-sensitive (tag names are case-sensitive per
    /// RFC 6376 §3.2, unlike header field names).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.ordered
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Iterate over all `(name, value)` pairs in original order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.ordered.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Serialise to `tag=value; tag=value` form.
    ///
    /// Tags are emitted in insertion order. No trailing semicolon is added.
    #[must_use]
    pub fn to_string_compact(&self) -> String {
        self.ordered
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Return a version of the serialised form with `b=` set to the empty
    /// string, as required when computing the hash input for the DKIM-Signature
    /// header (RFC 6376 §3.7 step 5).
    #[must_use]
    pub fn with_empty_b(&self) -> String {
        self.ordered
            .iter()
            .map(|(k, v)| {
                if k == "b" {
                    "b=".to_owned()
                } else {
                    format!("{k}={v}")
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::TagList;
    use crate::Error;

    /// RFC 6376 §3.2: basic tag-value list parsing.
    #[test]
    fn parse_basic() {
        let tl = TagList::parse("v=1; a=rsa-sha256; b=abc").expect("valid");
        assert_eq!(tl.get("v"), Some("1"));
        assert_eq!(tl.get("a"), Some("rsa-sha256"));
        assert_eq!(tl.get("b"), Some("abc"));
    }

    /// RFC 6376 §3.2: trailing semicolon is permitted.
    #[test]
    fn parse_trailing_semicolon() {
        let tl = TagList::parse("v=1; a=rsa-sha256;").expect("valid");
        assert_eq!(tl.iter().count(), 2);
    }

    /// RFC 6376 §3.2: whitespace (including FWS) around `=` and `;` is insignificant.
    #[test]
    fn parse_whitespace_stripped() {
        let tl = TagList::parse("  v = 1 ; a = rsa-sha256 ").expect("valid");
        assert_eq!(tl.get("v"), Some("1"));
        assert_eq!(tl.get("a"), Some("rsa-sha256"));
    }

    /// RFC 6376 §3.2: tag-value may be empty.
    #[test]
    fn parse_empty_value() {
        let tl = TagList::parse("v=; a=rsa-sha256").expect("valid");
        assert_eq!(tl.get("v"), Some(""));
        assert_eq!(tl.get("a"), Some("rsa-sha256"));
    }

    /// Empty input produces an empty `TagList`.
    #[test]
    fn parse_empty_input() {
        let tl = TagList::parse("").expect("valid");
        assert_eq!(tl.iter().count(), 0);
    }

    /// RFC 6376 §3.2 rule 5: duplicate tag names are a permerror.
    #[test]
    fn duplicate_rejected() {
        let err = TagList::parse("v=1; v=2").expect_err("duplicate");
        assert!(matches!(
            err,
            Error::InvalidTag {
                tag: "duplicate",
                ..
            }
        ));
    }

    /// RFC 6376 §3.2: tag name must start with ALPHA.
    #[test]
    fn invalid_name_rejected() {
        TagList::parse("1v=bad").expect_err("name starts with digit");
    }

    /// Missing `=` in a tag spec is a parse error.
    #[test]
    fn missing_equals() {
        TagList::parse("vbad").expect_err("no equals sign");
    }

    /// `get` returns `None` for an absent tag.
    #[test]
    fn get_missing() {
        let tl = TagList::parse("v=1").expect("valid");
        assert_eq!(tl.get("a"), None);
    }

    /// `iter` preserves insertion order.
    #[test]
    fn iter_order_preserved() {
        let tl = TagList::parse("b=2; a=1").expect("valid");
        let pairs: Vec<_> = tl.iter().collect();
        assert_eq!(pairs, vec![("b", "2"), ("a", "1")]);
    }

    /// `to_string_compact` round-trips a whitespace-free tag list.
    #[test]
    fn to_string_compact() {
        let tl = TagList::parse("v=1; a=rsa-sha256").expect("valid");
        assert_eq!(tl.to_string_compact(), "v=1; a=rsa-sha256");
    }

    /// `with_empty_b` replaces only the `b=` value with an empty string.
    #[test]
    fn with_empty_b() {
        let tl = TagList::parse("a=rsa-sha256; b=abc; d=example.com").expect("valid");
        assert_eq!(tl.with_empty_b(), "a=rsa-sha256; b=; d=example.com");
    }
}
