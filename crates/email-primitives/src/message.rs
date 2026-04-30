//! Top-level email message type.
//!
//! # Wire format
//!
//! Per RFC 5322 section 2.1, a message on the wire is:
//!
//! ```text
//! message   = (fields / obs-fields) CRLF body
//! body      = *(*998text CRLF) *998text
//! ```
//!
//! The header section and body are separated by exactly one blank line (a
//! bare `CRLF`). The body may contain arbitrary octets subject to line-length
//! limits, but in the context of DKIM/ARC signing, the body hash is computed
//! over the canonical body (RFC 6376 section 3.4).
//!
//! # Relationship to LMTP DATA transfer
//!
//! During LMTP `DATA` (RFC 2033), the client sends the message followed by a
//! lone `.` on a line by itself (`\r\n.\r\n`). The LMTP layer is responsible
//! for stripping the dot-stuffing before constructing a [`Message`].
//!
//! Dot-stuffing rule (RFC 5321 section 4.5.2): any line beginning with a `.`
//! has an extra `.` prepended. The receiver strips the leading `.` from any
//! line that begins with a `.` while reading the message, and stops when it
//! sees `\r\n.\r\n`.

use bytes::Bytes;

use crate::{Headers, Result};

/// A complete email message: header section plus body.
///
/// The message is stored in its wire form with `CRLF` line endings throughout.
/// Headers are parsed into the [`Headers`] structure; the body is kept as raw
/// bytes to avoid unnecessary copies and to preserve exact byte content for
/// hashing.
#[expect(
    clippy::exhaustive_structs,
    reason = "RFC 5322 provides for only two parts to a message"
)]
#[derive(Debug, Clone)]
pub struct Message {
    /// The parsed header fields in original wire order.
    pub headers: Headers,
    /// The raw message body with `CRLF` line endings.
    ///
    /// Does not include the header/body separator blank line. The body may be
    /// empty (RFC 5322 section 3.5 permits messages with no body).
    pub body: MessageBody,
}

impl Message {
    /// Construct a [`Message`] from pre-parsed components.
    #[must_use]
    pub const fn new(headers: Headers, body: MessageBody) -> Self {
        Self { headers, body }
    }

    /// Parse a complete message from a byte slice.
    ///
    /// Locates the header/body separator (`\r\n\r\n`), parses the header
    /// section, and wraps the remaining bytes as the body.
    ///
    /// # Errors
    ///
    /// Returns an error if the header section is malformed, or if the
    /// header/body separator is absent.
    pub fn parse(input: &Bytes) -> Result<Self> {
        // Headers::parse expects the blank line as its terminator.
        let (headers, body) = Headers::parse(input)?;

        Ok(Self {
            headers,
            body: MessageBody::new(body),
        })
    }

    /// Serialise the message back to wire-format bytes.
    ///
    /// Output is `<headers section>\r\n<body>` where the headers section
    /// already contains the per-field terminating `CRLF`s.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = Vec::with_capacity(self.wire_len());
        for header in self.headers.iter() {
            buf.extend_from_slice(header.to_wire().as_bytes());
        }
        buf.extend_from_slice(b"\r\n"); // blank line separator
        buf.extend_from_slice(self.body.as_bytes());
        Bytes::from(buf)
    }

    /// Return the total length of the message in bytes (wire representation).
    #[must_use]
    pub fn wire_len(&self) -> usize {
        // Allocation-free: name + ':' + value + CRLF for each header,
        // plus 2 bytes for the blank-line separator, plus body length.
        self.headers
            .iter()
            .map(|h| h.name.as_str().len() + 1 + h.value.as_str().len() + 2)
            .sum::<usize>()
            + 2
            + self.body.len()
    }
}

/// The body of an email message.
///
/// # DKIM body hashing (RFC 6376 section 3.4)
///
/// DKIM signs a hash of the (canonicalised) body. Two canonicalization
/// algorithms apply to the body:
///
/// - **simple** (RFC 6376 section 3.4.3): the body is unchanged except that
///   all trailing `CRLF` sequences are removed, then a single `CRLF` is appended.
///   An empty body is canonicalised to a single `CRLF`.
///
/// - **relaxed** (RFC 6376 section 3.4.4): runs of whitespace within each
///   line are compressed to a single SP; trailing whitespace is removed from
///   each line; trailing empty lines are removed; a single `CRLF` is appended.
///
/// The `l=` tag in DKIM-Signature allows signing only a prefix of the body
/// (by byte count of the **canonicalised** body). This is not recommended
/// because it enables replay attacks. Implementations MUST still verify the
/// prefix but SHOULD warn.
#[derive(Debug, Clone, Default)]
pub struct MessageBody(pub(crate) Bytes);

impl MessageBody {
    /// Construct a body from raw bytes.
    ///
    /// The bytes must use `CRLF` line endings. No validation is performed here;
    /// malformed line endings will produce incorrect DKIM body hashes.
    #[must_use]
    pub const fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }

    /// The raw bytes of the body.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The length of the body in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// True if the body is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod rfc5322_message {
    use super::*;

    fn simple_bytes() -> Bytes {
        Bytes::from_static(
            b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\n\r\nHello body\r\n",
        )
    }

    /// RFC 5322 §2.1: parse splits headers and body at the first `\r\n\r\n`.
    #[test]
    fn parse_splits_correctly() {
        let msg = Message::parse(&simple_bytes()).expect("valid message");
        assert_eq!(msg.headers.len(), 3);
        assert_eq!(msg.body.as_bytes(), b"Hello body\r\n");
    }

    /// RFC 5322 §3.5: an empty body is valid.
    #[test]
    fn parse_empty_body() {
        let input = Bytes::from_static(b"From: a@b.com\r\n\r\n");
        let msg = Message::parse(&input).expect("message with empty body");
        assert_eq!(msg.headers.len(), 1);
        assert!(msg.body.is_empty());
    }

    /// RFC 5322 §2.1: body may itself contain `\r\n\r\n`; only the first
    /// occurrence separates headers from body.
    #[test]
    fn crlf_in_body_not_confused_with_separator() {
        let input = Bytes::from_static(b"From: a@b.com\r\n\r\nPara 1\r\n\r\nPara 2\r\n");
        let msg = Message::parse(&input).expect("valid message");
        assert_eq!(msg.body.as_bytes(), b"Para 1\r\n\r\nPara 2\r\n");
    }

    /// Round-trip: parse → `to_bytes` must reproduce the original bytes exactly.
    #[test]
    fn round_trip() {
        let original = simple_bytes();
        let msg = Message::parse(&original).expect("valid message");
        let serialised = msg.to_bytes();
        assert_eq!(serialised, original);
    }

    /// `wire_len` must equal the length of `to_bytes()`.
    #[test]
    fn wire_len_matches_to_bytes() {
        let msg = Message::parse(&simple_bytes()).expect("valid message");
        assert_eq!(msg.wire_len(), msg.to_bytes().len());
    }

    /// RFC 5322 §2.1: missing `\r\n\r\n` separator is an error.
    #[test]
    fn reject_no_separator() {
        let input = Bytes::from_static(b"From: a@b.com\r\nNo separator here");
        Message::parse(&input).expect_err("missing header/body separator");
    }

    /// Body bytes are a zero-copy slice of the input `Bytes`.
    #[test]
    fn body_is_zero_copy_slice() {
        let original = simple_bytes();
        let msg = Message::parse(&original).expect("valid message");
        // The body slice should share the same underlying allocation.
        assert_eq!(
            msg.body.as_bytes().as_ptr() as usize,
            original[original
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("separator present")
                + 4..]
                .as_ptr() as usize
        );
    }
}
