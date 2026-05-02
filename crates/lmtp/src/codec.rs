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

use bytes::{Buf, BufMut, BytesMut};
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

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        // Find LF position; CRLF or bare LF both accepted (RFC 5321 §2.3.8).
        let Some(lf_pos) = src.iter().position(|&b| b == b'\n') else {
            // No complete line yet; enforce length limit against partial data.
            if src.len() >= self.max_line {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "command line too long",
                )));
            }
            return Ok(None);
        };

        // +1 to include the LF itself in the length check.
        let line_len = lf_pos + 1;
        if line_len > self.max_line {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "command line too long",
            )));
        }

        let mut line_bytes = src.split_to(line_len);
        // Strip trailing LF.
        line_bytes.truncate(line_bytes.len() - 1);
        // Strip trailing CR if present.
        if line_bytes.last() == Some(&b'\r') {
            line_bytes.truncate(line_bytes.len() - 1);
        }

        let line = std::str::from_utf8(&line_bytes)
            .map_err(|_utf8_err| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "command line is not valid UTF-8",
                ))
            })?
            .to_owned();

        Ok(Some(line))
    }
}

impl Encoder<&str> for CommandCodec {
    type Error = Error;

    fn encode(&mut self, item: &str, dst: &mut BytesMut) -> Result<()> {
        dst.reserve(item.len() + 2);
        dst.put(item.as_bytes());
        dst.put(&b"\r\n"[..]);
        Ok(())
    }
}

impl Encoder<crate::Reply> for CommandCodec {
    type Error = Error;

    fn encode(&mut self, item: crate::Reply, dst: &mut BytesMut) -> Result<()> {
        let wire = item.to_wire();
        dst.reserve(wire.len());
        dst.put(wire.as_bytes());
        Ok(())
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
    max_size: usize,
}

impl DataCodec {
    /// Construct a [`DataCodec`] with a configurable maximum message size.
    #[must_use]
    pub const fn new(max_size: usize) -> Self {
        Self { max_size }
    }
}

impl Encoder<bytes::Bytes> for DataCodec {
    type Error = Error;

    fn encode(&mut self, _item: bytes::Bytes, _dst: &mut BytesMut) -> Result<()> {
        Ok(())
    }
}

impl Decoder for DataCodec {
    type Item = bytes::Bytes;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() > self.max_size {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "message too large",
            )));
        }

        // The end-of-data terminator is <CRLF>.<CRLF> (RFC 5321 §4.5.2).
        // Two cases:
        //   a) `.\r\n` at the very start — empty body.
        //   b) `\r\n.\r\n` anywhere — the \r\n before the dot belongs to the body.
        let (body_end, consumed_end) = if src.starts_with(b".\r\n") {
            (0, 3)
        } else if let Some(pos) = find_bytes(src, b"\r\n.\r\n") {
            (pos + 2, pos + 5)
        } else {
            return Ok(None);
        };

        let raw_body = src[..body_end].to_vec();
        src.advance(consumed_end);

        let unstuffed = dot_unstuff(&raw_body);
        Ok(Some(bytes::Bytes::from(unstuffed)))
    }
}

/// Find the first occurrence of `needle` in `haystack`, returning its start index.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Remove the extra leading `.` from any line that begins with `..` (RFC 5321 §4.5.2).
fn dot_unstuff(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut start = 0;
    while start < body.len() {
        let end = find_bytes(&body[start..], b"\r\n").map_or(body.len(), |p| start + p);
        let line = &body[start..end];
        let line = if line.starts_with(b"..") {
            &line[1..]
        } else {
            line
        };
        out.extend_from_slice(line);
        if end < body.len() {
            out.extend_from_slice(b"\r\n");
            start = end + 2;
        } else {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

    use super::{CommandCodec, DataCodec, MAX_COMMAND_LINE};

    // ── CommandCodec ─────────────────────────────────────────────────────────

    /// RFC 5321 §2.3.8: CRLF is the standard line terminator.
    #[test]
    fn command_decode_basic() {
        let mut codec = CommandCodec::new();
        let mut buf = BytesMut::from("LHLO example.com\r\n");
        let line = codec
            .decode(&mut buf)
            .expect("decode ok")
            .expect("line present");
        assert_eq!(line, "LHLO example.com");
        assert!(buf.is_empty());
    }

    /// Returns `None` when no CRLF has arrived yet.
    #[test]
    fn command_decode_partial() {
        let mut codec = CommandCodec::new();
        let mut buf = BytesMut::from("NOOP");
        assert!(codec.decode(&mut buf).expect("decode ok").is_none());
    }

    /// Bare LF is accepted as a line terminator for robustness.
    #[test]
    fn command_decode_bare_lf() {
        let mut codec = CommandCodec::new();
        let mut buf = BytesMut::from("QUIT\n");
        let line = codec
            .decode(&mut buf)
            .expect("decode ok")
            .expect("line present");
        assert_eq!(line, "QUIT");
    }

    /// RFC 5321 §4.5.3.1: command lines longer than 512 bytes are rejected.
    #[test]
    fn command_decode_too_long() {
        let mut codec = CommandCodec::new();
        let long: String = "A".repeat(MAX_COMMAND_LINE) + "\r\n";
        let mut buf = BytesMut::from(long.as_str());
        codec.decode(&mut buf).expect_err("line exceeds 512 bytes");
    }

    /// Encoder appends CRLF.
    #[test]
    fn command_encode() {
        let mut codec = CommandCodec::new();
        let mut buf = BytesMut::new();
        codec.encode("250 OK", &mut buf).expect("encode ok");
        assert_eq!(&buf[..], b"250 OK\r\n");
    }

    // ── DataCodec ────────────────────────────────────────────────────────────

    /// Empty body: client sends `.\r\n` immediately after DATA.
    #[test]
    fn data_decode_empty_body() {
        let mut codec = DataCodec::new(1024);
        let mut buf = BytesMut::from(".\r\n");
        let body = codec
            .decode(&mut buf)
            .expect("decode ok")
            .expect("body present");
        assert!(body.is_empty());
        assert!(buf.is_empty());
    }

    /// Single-line body terminated by `\r\n.\r\n`.
    #[test]
    fn data_decode_simple() {
        let mut codec = DataCodec::new(1024);
        let mut buf = BytesMut::from("Hello world\r\n.\r\n");
        let body = codec
            .decode(&mut buf)
            .expect("decode ok")
            .expect("body present");
        assert_eq!(&body[..], b"Hello world\r\n");
        assert!(buf.is_empty());
    }

    /// RFC 5321 §4.5.2: lines starting with `..` have the leading `.` stripped.
    #[test]
    fn data_decode_dot_unstuffing() {
        let mut codec = DataCodec::new(1024);
        let mut buf = BytesMut::from("line1\r\n..dotline\r\n.\r\n");
        let body = codec
            .decode(&mut buf)
            .expect("decode ok")
            .expect("body present");
        assert_eq!(&body[..], b"line1\r\n.dotline\r\n");
    }

    /// Returns `None` when the terminator has not yet been seen.
    #[test]
    fn data_decode_partial() {
        let mut codec = DataCodec::new(1024);
        let mut buf = BytesMut::from("incomplete data");
        assert!(codec.decode(&mut buf).expect("decode ok").is_none());
    }

    /// Returns an error when the buffered data exceeds `max_size`.
    #[test]
    fn data_decode_too_large() {
        let mut codec = DataCodec::new(10);
        let mut buf = BytesMut::from("this is definitely more than ten bytes of data");
        codec.decode(&mut buf).expect_err("body exceeds max_size");
    }

    /// Remaining bytes after the terminator are left in the buffer.
    #[test]
    fn data_decode_leaves_remainder() {
        let mut codec = DataCodec::new(1024);
        let mut buf = BytesMut::from("body\r\n.\r\nNEXT");
        let body = codec
            .decode(&mut buf)
            .expect("decode ok")
            .expect("body present");
        assert_eq!(&body[..], b"body\r\n");
        assert_eq!(&buf[..], b"NEXT");
    }
}
