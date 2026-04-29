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
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let s: String = name.into();
        if s.is_empty() {
            return Err(Error::InvalidHeaderName(s));
        }
        for b in s.bytes() {
            // RFC 5322 §2.2: ftext = %d33-126, excluding ':'
            if !(33..=126).contains(&b) || b == b':' {
                return Err(Error::InvalidHeaderName(s));
            }
        }
        Ok(HeaderName(s))
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
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let s: String = value.into();
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'\r' => {
                    // RFC 5322 §2.2: CR must be followed by LF then WSP (fold).
                    let ok = i + 2 < bytes.len()
                        && bytes[i + 1] == b'\n'
                        && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t');
                    if !ok {
                        return Err(Error::InvalidHeaderValue(s));
                    }
                    i += 3;
                }
                b'\n' => {
                    // Bare LF is never valid in a header value.
                    return Err(Error::InvalidHeaderValue(s));
                }
                _ => i += 1,
            }
        }
        Ok(HeaderValue(s))
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
        // RFC 5322 §2.2.3: "remove any CRLF that is immediately followed by WSP".
        // Removing "\r\n" leaves the WSP character in place, which is correct.
        self.0.replace("\r\n ", " ").replace("\r\n\t", "\t")
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
    pub fn parse(input: &[u8]) -> Result<Self> {
        // Find the first ':' to split name from value.
        let colon =
            input
                .iter()
                .position(|&b| b == b':')
                .ok_or_else(|| Error::MalformedMessage {
                    reason: "header field has no ':' separator".to_owned(),
                })?;

        let name_bytes = &input[..colon];
        let name_str = std::str::from_utf8(name_bytes).map_err(|_| Error::MalformedMessage {
            reason: "non-UTF-8 header field name".to_owned(),
        })?;
        let name = HeaderName::new(name_str)?;

        // Value is everything after ':' up to (but not including) the final CRLF.
        let value_bytes = &input[colon + 1..];
        let value_str = std::str::from_utf8(value_bytes).map_err(|_| Error::MalformedMessage {
            reason: "non-UTF-8 header field value".to_owned(),
        })?;
        // Strip exactly the trailing CRLF (folds inside are preserved).
        let value_str = value_str.strip_suffix("\r\n").unwrap_or(value_str);
        let value = HeaderValue::new(value_str)?;

        Ok(Header { name, value })
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
    pub fn parse(input: &[u8]) -> Result<(Self, &[u8])> {
        let mut headers = Headers::new();
        let mut pos = 0;

        loop {
            // Blank line (CRLF with nothing before it) marks end of headers.
            if input[pos..].starts_with(b"\r\n") {
                return Ok((headers, &input[pos + 2..]));
            }
            if pos >= input.len() {
                return Err(Error::MalformedMessage {
                    reason: "header section not terminated by blank line".to_owned(),
                });
            }

            let header_start = pos;
            let header_end = find_header_end(input, pos)?;
            let header = Header::parse(&input[header_start..header_end])?;
            headers.push(header);
            pos = header_end;
        }
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

/// Find the byte index of the end of the current header field (including the
/// terminating CRLF), scanning forward from `start`.
///
/// Continuation lines (lines beginning with WSP after a CRLF) are included
/// in the returned range per RFC 5322 §2.2.3 folding rules.
fn find_header_end(input: &[u8], start: usize) -> Result<usize> {
    let mut pos = start;
    loop {
        // Locate the next CRLF.
        let crlf = input[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| Error::MalformedMessage {
                reason: "header field not terminated with CRLF".to_owned(),
            })?;
        pos += crlf + 2; // advance past the CRLF

        // If the next byte is WSP this is a fold; include the continuation.
        match input.get(pos) {
            Some(&b' ') | Some(&b'\t') => continue,
            _ => return Ok(pos),
        }
    }
}

#[cfg(test)]
mod rfc5322_header_name {
    use super::*;

    /// RFC 5322 §2.2: valid ftext characters (33-126 except ':').
    #[test]
    fn valid_names() {
        HeaderName::new("Subject").unwrap();
        HeaderName::new("DKIM-Signature").unwrap();
        HeaderName::new("X-Custom-Header").unwrap();
        HeaderName::new("From").unwrap();
    }

    /// RFC 5322 §2.2: colon is not allowed in field name.
    #[test]
    fn reject_colon() {
        assert!(HeaderName::new("Sub:ject").is_err());
    }

    /// RFC 5322 §2.2: space (char 32) is below the ftext floor.
    #[test]
    fn reject_space() {
        assert!(HeaderName::new("Sub ject").is_err());
    }

    /// RFC 5322 §2.2: DEL (char 127) is above the ftext ceiling.
    #[test]
    fn reject_del() {
        assert!(HeaderName::new("Sub\x7fject").is_err());
    }

    /// RFC 5322 §2.2: empty string is not a valid field name.
    #[test]
    fn reject_empty() {
        assert!(HeaderName::new("").is_err());
    }

    /// RFC 5322 §2.2: field names are case-insensitive.
    #[test]
    fn case_insensitive_eq() {
        let a = HeaderName::new("Subject").unwrap();
        let b = HeaderName::new("SUBJECT").unwrap();
        assert_eq!(a, b);
    }

    /// RFC 6376 §3.4.2: to_lowercase() for relaxed canonicalization.
    #[test]
    fn to_lowercase() {
        let n = HeaderName::new("DKIM-Signature").unwrap();
        assert_eq!(n.to_lowercase(), "dkim-signature");
    }
}

#[cfg(test)]
mod rfc5322_header_value {
    use super::*;

    /// RFC 5322 §2.2: a simple ASCII value is accepted.
    #[test]
    fn valid_simple() {
        HeaderValue::new(" Hello, world!").unwrap();
    }

    /// RFC 5322 §2.2.3: CRLF followed by SP is a valid fold.
    #[test]
    fn valid_fold_sp() {
        HeaderValue::new(" value\r\n continued").unwrap();
    }

    /// RFC 5322 §2.2.3: CRLF followed by HTAB is a valid fold.
    #[test]
    fn valid_fold_htab() {
        HeaderValue::new(" value\r\n\tcontinued").unwrap();
    }

    /// RFC 5322 §2.2: bare CR is not allowed.
    #[test]
    fn reject_bare_cr() {
        assert!(HeaderValue::new(" val\rue").is_err());
    }

    /// RFC 5322 §2.2: bare LF is not allowed.
    #[test]
    fn reject_bare_lf() {
        assert!(HeaderValue::new(" val\nue").is_err());
    }

    /// RFC 5322 §2.2: CRLF not followed by WSP is rejected.
    #[test]
    fn reject_crlf_without_wsp() {
        assert!(HeaderValue::new(" val\r\nue").is_err());
    }

    /// RFC 5322 §2.2.3: unfold removes CRLF before SP, keeping the SP.
    #[test]
    fn unfold_sp() {
        let v = HeaderValue::new(" value\r\n continued").unwrap();
        assert_eq!(v.unfold(), " value continued");
    }

    /// RFC 5322 §2.2.3: unfold removes CRLF before HTAB, keeping the HTAB.
    #[test]
    fn unfold_htab() {
        let v = HeaderValue::new(" value\r\n\tcontinued").unwrap();
        assert_eq!(v.unfold(), " value\tcontinued");
    }

    /// RFC 5322 §2.2.3: multiple folds are all removed.
    #[test]
    fn unfold_multiple() {
        let v = HeaderValue::new(" a\r\n b\r\n c").unwrap();
        assert_eq!(v.unfold(), " a b c");
    }
}

#[cfg(test)]
mod rfc5322_header_parse {
    use super::*;

    /// RFC 5322 §2.2: parse a simple non-folded header field.
    #[test]
    fn parse_simple() {
        let h = Header::parse(b"Subject: Hello\r\n").unwrap();
        assert_eq!(h.name.as_str(), "Subject");
        assert_eq!(h.value.as_str(), " Hello");
    }

    /// RFC 5322 §2.2.3: parse a folded header field preserving the fold.
    #[test]
    fn parse_folded() {
        let h = Header::parse(b"Subject: Hello\r\n world\r\n").unwrap();
        assert_eq!(h.name.as_str(), "Subject");
        assert!(h.value.as_str().contains("\r\n"));
        assert_eq!(h.value.unfold(), " Hello world");
    }

    /// RFC 5322 §2.2: wire round-trip restores the original bytes.
    #[test]
    fn wire_round_trip() {
        let original = "Subject: Hello\r\n";
        let h = Header::parse(original.as_bytes()).unwrap();
        assert_eq!(h.to_wire(), original);
    }

    /// RFC 5322 §2.2: leading space after colon is part of value.
    #[test]
    fn leading_space_in_value() {
        let h = Header::parse(b"From: alice@example.com\r\n").unwrap();
        assert_eq!(h.value.as_str(), " alice@example.com");
    }
}

#[cfg(test)]
mod rfc5322_headers_parse {
    use super::*;

    /// RFC 5322 §2.1: headers section terminated by blank line (CRLF CRLF).
    #[test]
    fn parse_basic() {
        let input = b"From: alice@example.com\r\nTo: bob@example.com\r\n\r\nBody here";
        let (headers, body) = Headers::parse(input).unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(body, b"Body here");
    }

    /// RFC 5322 §2.1: empty header section (blank line only) is valid.
    #[test]
    fn parse_empty_headers() {
        let input = b"\r\nBody";
        let (headers, body) = Headers::parse(input).unwrap();
        assert_eq!(headers.len(), 0);
        assert_eq!(body, b"Body");
    }

    /// RFC 5322 §2.2.3: folded header is parsed as a single field.
    #[test]
    fn parse_folded_header() {
        let input = b"Subject: Hello\r\n world\r\n\r\n";
        let (headers, _) = Headers::parse(input).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.iter().next().unwrap().name.as_str(), "Subject");
    }

    /// RFC 6376 §5.4.2: insertion order is preserved (top to bottom).
    #[test]
    fn insertion_order_preserved() {
        let input = b"From: a\r\nReceived: x\r\nReceived: y\r\n\r\n";
        let (headers, _) = Headers::parse(input).unwrap();
        let name = HeaderName::new("Received").unwrap();
        let received: Vec<_> = headers.get_all(&name).map(|h| h.value.as_str()).collect();
        assert_eq!(received, [" x", " y"]);
    }

    /// RFC 6376 §5.4.2: get_last returns the bottommost occurrence.
    #[test]
    fn get_last_bottommost() {
        let input = b"From: first\r\nFrom: second\r\n\r\n";
        let (headers, _) = Headers::parse(input).unwrap();
        let name = HeaderName::new("From").unwrap();
        let last = headers.get_last(&name).unwrap();
        assert_eq!(last.value.as_str(), " second");
    }

    /// RFC 5322 §2.1: missing blank-line terminator is an error.
    #[test]
    fn reject_missing_terminator() {
        let result = Headers::parse(b"From: alice@example.com\r\n");
        assert!(result.is_err());
    }

    /// Body bytes after the blank line are returned unmodified.
    #[test]
    fn body_returned_correctly() {
        let input = b"From: a\r\n\r\nHello\r\nWorld\r\n";
        let (_, body) = Headers::parse(input).unwrap();
        assert_eq!(body, b"Hello\r\nWorld\r\n");
    }
}
