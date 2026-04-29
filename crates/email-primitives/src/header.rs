//! Email header field types per RFC 5322.
//!
//! # Header field structure
//!
//! RFC 5322 section 2.2 defines a header field as:
//!
//! ```text
//! header-field = field-name ":" unstructured CRLF
//! field-name   = 1*ftext           ; printable US-ASCII except ":"
//! unstructured = *([FWS] VCHAR)
//! ```
//!
//! # Folding and unfolding
//!
//! Long header values may be "folded" across multiple lines. A fold is a CRLF
//! followed by at least one WSP (SP or HTAB) character. Unfolding reverses
//! this by removing the CRLF before each WSP (RFC 5322 section 2.2.3).
//!
//! DKIM and ARC both work on **unfolded** header values when canonicalising,
//! then re-add their own folding in the generated signature headers.
//!
//! # Ordering and multiplicity
//!
//! Some header fields may appear multiple times (e.g. `Received:`,
//! `DKIM-Signature:`). The order of headers is significant for DKIM: the
//! `h=` tag lists headers in the order they were signed, and duplicate
//! headers are processed bottom-up (RFC 6376 section 5.4.2).
//!
//! [`Headers`] is an ordered list that preserves insertion order and allows
//! duplicates.

use crate::{Error, Result};

/// The name portion of a header field (`field-name` per RFC 5322 section 2.2).
///
/// Field names are case-insensitive (RFC 5322 section 2.2). We store them in
/// their original casing but provide case-insensitive comparison.
///
/// # DKIM canonicalization
///
/// Under **relaxed** header canonicalization (RFC 6376 section 3.4.2), field
/// names are lowercased before hashing. Under **simple** canonicalization, the
/// original casing is preserved.
#[derive(Debug, Clone)]
pub struct HeaderName(pub(crate) String);

impl HeaderName {
    /// Construct a header name, validating that it contains only printable
    /// ASCII characters other than `:` (RFC 5322 section 2.2 `ftext`).
    pub fn new(_name: impl Into<String>) -> Result<Self> {
        todo!("validate: chars in 33..=126 and char != ':'")
    }

    /// The field name in its original casing.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The field name lowercased, for case-insensitive comparisons and DKIM
    /// relaxed canonicalization.
    pub fn to_lowercase(&self) -> String {
        self.0.to_ascii_lowercase()
    }
}

impl PartialEq for HeaderName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for HeaderName {}

impl std::hash::Hash for HeaderName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_ascii_lowercase().hash(state);
    }
}

impl std::fmt::Display for HeaderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The value portion of a header field.
///
/// Stored with its original folding intact (CRLF WSP sequences). Use
/// [`HeaderValue::unfold`] to obtain a single logical line. The leading space
/// after the colon is included in the stored value to preserve round-trip
/// fidelity.
///
/// # DKIM note
///
/// When DKIM signs or verifies a header, the full `name: value` line (with
/// trailing CRLF but **without** the terminating CRLF of the DKIM-Signature
/// itself) is included in the hash input. See RFC 6376 section 3.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderValue(pub(crate) String);

impl HeaderValue {
    /// Construct a header value from a raw string.
    ///
    /// The value must not contain bare CR or LF outside of CRLF-WSP folding
    /// sequences (RFC 5322 section 2.2).
    pub fn new(_value: impl Into<String>) -> Result<Self> {
        todo!("validate: no bare CR/LF; only CRLF followed by WSP is allowed")
    }

    /// The value with original folding preserved.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unfold the value by removing CRLF sequences that are followed by WSP
    /// (RFC 5322 section 2.2.3).
    ///
    /// The result is a single logical line with all inter-line whitespace
    /// collapsed to single spaces.
    pub fn unfold(&self) -> String {
        todo!("remove CRLF WSP sequences; collapse to single WSP")
    }
}

impl std::fmt::Display for HeaderValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A single header field: name, colon, value.
///
/// The wire representation (for hashing and serialisation) is:
/// `{name}:{value}\r\n`
///
/// Note that the value typically starts with a space (e.g. `Subject: Hello`),
/// and that space is part of the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The field name.
    pub name: HeaderName,
    /// The field value, including any leading whitespace and folding.
    pub value: HeaderValue,
}

impl Header {
    /// Construct a header from a name and value.
    pub fn new(name: HeaderName, value: HeaderValue) -> Self {
        Self { name, value }
    }

    /// Parse a single header field line (or folded multiline header) from a
    /// byte slice.
    ///
    /// The input should include the terminating CRLF of the final line but
    /// must NOT include the blank line that separates headers from the body.
    pub fn parse(_input: &[u8]) -> Result<Self> {
        todo!("winnow parser: field-name \":\" unstructured CRLF *(WSP unstructured CRLF)")
    }

    /// Render the header to its wire form: `{name}:{value}\r\n`.
    ///
    /// Consumers should not add an extra CRLF; the trailing CRLF is included.
    pub fn to_wire(&self) -> String {
        format!("{}:{}\r\n", self.name, self.value)
    }
}

impl std::fmt::Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.name, self.value)
    }
}

/// An ordered, multi-valued collection of header fields.
///
/// Preserves insertion order because:
/// 1. RFC 5322 permits multiple occurrences of some field names.
/// 2. DKIM (RFC 6376 section 5.4.2) processes duplicate headers bottom-up:
///    the second occurrence of `From:` in `h=` refers to the second-from-
///    bottom `From:` header in the message.
///
/// Lookups by name are O(n) over all headers but are expected to be infrequent
/// relative to message volume.
#[derive(Debug, Clone, Default)]
pub struct Headers(Vec<Header>);

impl Headers {
    /// Construct an empty header list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a header field at the end (logically, the bottom of the header
    /// section).
    pub fn push(&mut self, header: Header) {
        self.0.push(header);
    }

    /// Return an iterator over all headers in insertion order (top to bottom).
    pub fn iter(&self) -> impl Iterator<Item = &Header> {
        self.0.iter()
    }

    /// Return an iterator over all headers with the given name, in insertion
    /// order (top to bottom).
    pub fn get_all<'a>(&'a self, name: &'a HeaderName) -> impl Iterator<Item = &'a Header> {
        self.0.iter().filter(move |h| &h.name == name)
    }

    /// Return the last header with the given name, or `None`.
    ///
    /// "Last" means the bottommost occurrence in the header section, which is
    /// the canonical value for most singular header fields.
    pub fn get_last(&self, name: &HeaderName) -> Option<&Header> {
        self.0.iter().rev().find(|h| &h.name == name)
    }

    /// Parse a complete header section from a byte slice.
    ///
    /// The input must end with the blank line (`\r\n`) that separates the
    /// header section from the body. That blank line is consumed but not
    /// included in the returned [`Headers`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the header section is
    /// syntactically invalid.
    pub fn parse(_input: &[u8]) -> Result<(Self, &[u8])> {
        todo!("parse header fields until CRLF CRLF; return remaining bytes as body")
    }

    /// Return the number of header fields.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` if there are no header fields.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
