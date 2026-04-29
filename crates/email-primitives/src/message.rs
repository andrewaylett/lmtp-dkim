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
//! bare CRLF). The body may contain arbitrary octets subject to line-length
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
/// The message is stored in its wire form with CRLF line endings throughout.
/// Headers are parsed into the [`Headers`] structure; the body is kept as raw
/// bytes to avoid unnecessary copies and to preserve exact byte content for
/// hashing.
#[derive(Debug, Clone)]
pub struct Message {
    /// The parsed header fields in original wire order.
    pub headers: Headers,
    /// The raw message body with CRLF line endings.
    ///
    /// Does not include the header/body separator blank line. The body may be
    /// empty (RFC 5322 section 3.5 permits messages with no body).
    pub body: MessageBody,
}

impl Message {
    /// Construct a [`Message`] from pre-parsed components.
    pub fn new(headers: Headers, body: MessageBody) -> Self {
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
    pub fn parse(_input: Bytes) -> Result<Self> {
        todo!("split at first CRLF CRLF; parse Headers; wrap remainder as MessageBody")
    }

    /// Serialise the message back to wire-format bytes.
    ///
    /// Output is `<headers section>\r\n<body>` where the headers section
    /// already contains the per-field terminating CRLFs.
    pub fn to_bytes(&self) -> Bytes {
        todo!("concatenate header wire forms + CRLF + body bytes")
    }

    /// Return the total length of the message in bytes (wire representation).
    pub fn wire_len(&self) -> usize {
        todo!()
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
///   all trailing CRLF sequences are removed, then a single CRLF is appended.
///   An empty body is canonicalised to a single CRLF.
///
/// - **relaxed** (RFC 6376 section 3.4.4): runs of whitespace within each
///   line are compressed to a single SP; trailing whitespace is removed from
///   each line; trailing empty lines are removed; a single CRLF is appended.
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
    /// The bytes must use CRLF line endings. No validation is performed here;
    /// malformed line endings will produce incorrect DKIM body hashes.
    pub fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }

    /// The raw bytes of the body.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The length of the body in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if the body is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
