use crate::address;
use winnow::Parser;
use winnow::combinator::alt;

/// The local part of an email address (left of `@`).
///
/// Per RFC 5321 section 4.1.2, the local part is either a `dot-atom` or a
/// `quoted-string`. We preserve the original representation including any
/// quoting. Two local parts that compare equal as strings are equal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocalPart(pub(crate) String);

impl LocalPart {
    /// The raw string value, preserving original quoting.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LocalPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Parse the local-part of an address (dot-atom or quoted-string).
pub(crate) fn parse_local_part(s: &str) -> Option<LocalPart> {
    let mut input = s;
    let result = alt((address::dot_atom, address::quoted_string)).parse_next(&mut input);
    match result {
        Ok(matched) if input.is_empty() && matched == s => Some(LocalPart(s.to_owned())),
        _ => None,
    }
}
