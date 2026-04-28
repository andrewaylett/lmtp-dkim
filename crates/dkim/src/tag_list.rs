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

use std::collections::HashMap;

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
    /// Returns [`Error::TagListParse`] on syntax errors.
    /// Returns [`Error::InvalidTag`] with `tag = "duplicate"` if a tag name
    /// appears more than once (RFC 6376 §3.2 rule 5).
    pub fn parse(_input: &str) -> Result<Self> {
        todo!(
            "winnow parser: split on ';'; for each part split on first '='; \
             strip FWS; check no duplicate names"
        )
    }

    /// Retrieve the value of a tag by name, or `None` if absent.
    ///
    /// The name comparison is case-sensitive (tag names are case-sensitive per
    /// RFC 6376 §3.2, unlike header field names).
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
