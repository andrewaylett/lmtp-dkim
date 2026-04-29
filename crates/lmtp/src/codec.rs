//! Tokio codec for LMTP framing.
//!
//! LMTP (like SMTP) has two distinct framing modes:
//!
//! 1. **Command mode**: lines terminated by CRLF (`\r\n`). Each line is one
//!    complete command or server reply.
//!
//! 2. **Data mode**: the message body, terminated by a lone `.` on a line by
//!    itself (`\r\n.\r\n`). Within the body, any line beginning with `.` has
//!    an extra `.` prepended by the client (dot-stuffing, RFC 5321 §4.5.2).
//!    The receiver strips the leading `.` from such lines.
//!
//! # Implementation approach
//!
//! We implement two separate [`tokio_util::codec::Decoder`] types, switching
//! between them as the session state changes:
//!
//! - [`CommandCodec`]: decodes one CRLF-terminated line per call. Returns a
//!   `String` (the line, without the CRLF).
//!
//! - [`DataCodec`]: accumulates bytes until `\r\n.\r\n`, applies dot-
//!   unstuffing, and returns the complete message body as [`bytes::Bytes`].
//!
//! The [`crate::server`] and [`crate::session`] layers are responsible for
//! swapping the active codec at the appropriate point in the conversation.
//!
//! # Line length limits
//!
//! RFC 5321 section 4.5.3.1 specifies:
//! - Command lines: max 512 bytes (including CRLF).
//! - Reply lines: max 512 bytes (including CRLF).
//! - Text line in data: max 1000 bytes (including CRLF).
//!
//! We enforce command-line limits in [`CommandCodec`] and data-line limits in
//! [`DataCodec`] to protect against resource exhaustion.

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use crate::{Error, Result};

/// Maximum command/reply line length including CRLF (RFC 5321 §4.5.3.1).
pub const MAX_COMMAND_LINE: usize = 512;
/// Maximum data line length including CRLF (RFC 5321 §4.5.3.1).
pub const MAX_DATA_LINE: usize = 1000;
/// Maximum total message size we will accept (configurable via [`crate::ServerConfig`]).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024; // 50 MiB

/// Decodes CRLF-terminated command/reply lines.
///
/// Returns `Some(String)` containing the line text without the trailing CRLF
/// when a complete line is available, or `None` when more data is needed.
///
/// Bare LF (`\n` without preceding `\r`) is accepted as a line terminator for
/// robustness, but servers SHOULD NOT produce it. RFC 5321 section 2.3.8
/// requires CRLF on the wire.
#[derive(Debug, Default)]
pub struct CommandCodec {
    /// Maximum line length before returning an error.
    #[expect(dead_code, reason = "stub: enforced in decode() once implemented")]
    max_line: usize,
}

impl CommandCodec {
    /// Construct a [`CommandCodec`] with the default command-line length limit.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_line: MAX_COMMAND_LINE,
        }
    }
}

impl Decoder for CommandCodec {
    type Item = String;
    type Error = Error;

    fn decode(&mut self, _src: &mut BytesMut) -> Result<Option<Self::Item>> {
        todo!(
            "scan for \\r\\n; check length <= self.max_line; \
             strip \\r\\n; return UTF-8 string or Io error"
        )
    }
}

impl Encoder<&str> for CommandCodec {
    type Error = Error;

    fn encode(&mut self, _item: &str, _dst: &mut BytesMut) -> Result<()> {
        todo!("write item + \\r\\n into dst")
    }
}

/// Decodes a SMTP/LMTP `DATA` body terminated by `\\r\\n.\\r\\n`.
///
/// Applies dot-unstuffing: if a line begins with `..`, the leading `.` is
/// stripped. Returns the complete unstuffed body as [`bytes::Bytes`] once the
/// terminator is seen.
#[derive(Debug)]
pub struct DataCodec {
    /// Maximum total body size before returning an error.
    #[expect(dead_code, reason = "stub: enforced in decode() once implemented")]
    max_size: usize,
}

impl DataCodec {
    /// Construct a [`DataCodec`] with a configurable maximum message size.
    #[must_use]
    pub const fn new(max_size: usize) -> Self {
        Self { max_size }
    }
}

impl Decoder for DataCodec {
    type Item = bytes::Bytes;
    type Error = Error;

    fn decode(&mut self, _src: &mut BytesMut) -> Result<Option<Self::Item>> {
        todo!(
            "scan for \\r\\n.\\r\\n terminator; \
             apply dot-unstuffing line by line; \
             enforce max_size; \
             return Bytes of the unstuffed body"
        )
    }
}
