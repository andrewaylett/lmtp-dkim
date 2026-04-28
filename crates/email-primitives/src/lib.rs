//! Primitive types for email processing shared across the workspace.
//!
//! This crate contains the foundational data structures for email messages.
//! Every type is designed to map directly onto concepts defined in the RFCs so
//! that correctness arguments can cite specific sections.
//!
//! # Canonical RFCs
//!
//! | RFC  | Title |
//! |------|-------|
//! | [RFC 5321] | Simple Mail Transfer Protocol (SMTP) |
//! | [RFC 5322] | Internet Message Format |
//! | [RFC 6532] | Internationalized Email Headers (UTF-8 in headers) |
//! | [RFC 2045] | MIME Part One: Format of Internet Message Bodies |
//!
//! [RFC 5321]: https://www.rfc-editor.org/rfc/rfc5321
//! [RFC 5322]: https://www.rfc-editor.org/rfc/rfc5322
//! [RFC 6532]: https://www.rfc-editor.org/rfc/rfc6532
//! [RFC 2045]: https://www.rfc-editor.org/rfc/rfc2045
//!
//! # Message structure
//!
//! Per RFC 5322 section 2.1, a message is:
//!
//! ```text
//! message = (fields / obs-fields) CRLF body
//! ```
//!
//! Header fields and the body are separated by a single blank line (`CRLF`).
//! Header field lines may be folded across multiple lines using "folded
//! whitespace" (FWS) – a CRLF followed by at least one WSP character.
//!
//! # Line endings
//!
//! SMTP and LMTP always use CRLF (`\r\n`) line endings on the wire
//! (RFC 5321 section 2.3.8). This crate stores messages with CRLF endings
//! to match wire format. Implementations that receive messages without CRLF
//! (e.g. from local filesystem) must normalise before processing.
//!
//! # Module layout
//!
//! - [`address`] – email addresses and domain names
//! - [`header`]  – header field types, folding/unfolding, ordered collections
//! - [`message`] – top-level [`Message`] type combining headers and body

#![warn(missing_docs)]

pub mod address;
pub mod error;
pub mod header;
pub mod message;

pub use address::{Domain, EmailAddress, LocalPart, NullPath, ReversePath};
pub use error::Error;
pub use header::{Header, HeaderName, HeaderValue, Headers};
pub use message::{Message, MessageBody};

/// Convenience `Result` alias using this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
