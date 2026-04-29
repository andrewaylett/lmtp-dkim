//! Error types for email primitive parsing and validation.

use thiserror::Error;

/// Errors arising from parsing or validating email primitives.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// A header field name contained characters outside the printable US-ASCII
    /// range 33–126 or included a colon (RFC 5322 section 2.2).
    #[error("invalid header name: {0:?}")]
    InvalidHeaderName(String),

    /// A header field value contained bare CR or LF outside of folded
    /// whitespace (RFC 5322 section 2.2).
    #[error("invalid header value: {0:?}")]
    InvalidHeaderValue(String),

    /// An email address could not be parsed per RFC 5321 section 4.1.2.
    #[error("invalid email address: {0:?}")]
    InvalidAddress(String),

    /// A domain name was syntactically invalid (RFC 5321 section 4.1.2,
    /// RFC 1123 section 2.1).
    #[error("invalid domain: {0:?}")]
    InvalidDomain(String),

    /// The message was not structurally well-formed (e.g. missing header/body
    /// separator, truncated header section).
    #[error("malformed message: {reason}")]
    MalformedMessage {
        /// Human-readable description of the problem.
        reason: String,
    },
}
