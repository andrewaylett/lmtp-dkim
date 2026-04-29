//! DKIM signing and verification per RFC 6376 and RFC 8463.
//!
//! # Overview
//!
//! `DomainKeys` Identified Mail (DKIM) lets a domain take responsibility for a
//! message by attaching a cryptographic signature in a `DKIM-Signature` header
//! field. Receiving MTAs (and milters) verify the signature by fetching the
//! corresponding public key from DNS.
//!
//! # Signing algorithm (RFC 6376 §3)
//!
//! 1. **Select headers** (`h=` tag): choose which header fields to cover.
//!    `From:` is mandatory. Each name in `h=` selects one header, consumed
//!    bottom-up if the same name appears multiple times.
//!
//! 2. **Canonicalise the body** (§3.4): apply `simple` or `relaxed` algorithm;
//!    compute SHA-256 hash → `bh=` tag.
//!
//! 3. **Canonicalise the selected headers** (§3.4): produce the hash input
//!    `data-to-sign = canonicalized-header-block || canonical-DKIM-Signature`.
//!    The DKIM-Signature header is included with `b=` left empty.
//!
//! 4. **Sign** `data-to-sign` with the private key → `b=` tag.
//!
//! 5. **Prepend** the completed `DKIM-Signature` header to the message.
//!
//! # Verification algorithm (RFC 6376 §6)
//!
//! 1. Extract all `DKIM-Signature` headers (there may be multiple).
//! 2. For each signature (in order): parse the tag-list; fetch the public key
//!    from DNS; canonicalise the body and check `bh=`; canonicalise the signed
//!    headers; verify the signature; record the result.
//! 3. Return the best result across all signatures.
//!
//! # Supported algorithms
//!
//! | Algorithm tag | RFC | Notes |
//! |---------------|-----|-------|
//! | `rsa-sha256`  | RFC 6376 §3.3.1 | RSA PKCS#1 v1.5, SHA-256, ≥1024-bit key |
//! | `ed25519-sha256` | RFC 8463 §3 | Ed25519, SHA-256 pre-hash |
//!
//! `rsa-sha1` (RFC 6376 §3.3.2) is listed for completeness but MUST NOT be
//! used for new signatures and SHOULD be treated as a `permerror` on
//! verification (RFC 8301).
//!
//! # Canonicalization
//!
//! Two algorithms apply independently to headers and body:
//!
//! | Algorithm | Header treatment | Body treatment |
//! |-----------|-----------------|----------------|
//! | `simple`  | Names and values unchanged | Strip trailing CRLFs; append one CRLF |
//! | `relaxed` | Lowercase names; normalise WSP | Compress WSP; strip trailing; append CRLF |
//!
//! The `c=` tag encodes `<header>/<body>`, e.g. `relaxed/relaxed`.
//!
//! [RFC 6376]: https://www.rfc-editor.org/rfc/rfc6376
//! [RFC 8463]: https://www.rfc-editor.org/rfc/rfc8463
//! [RFC 8301]: https://www.rfc-editor.org/rfc/rfc8301
//!
//! # Module layout
//!
//! - [`tag_list`]     – parse/serialise the `tag=value; ...` format used in
//!   DKIM headers (RFC 6376 §3.2).
//! - [`signature`]    – the `DKIM-Signature` header field and its typed tags.
//! - [`canonicalize`] – header and body canonicalization algorithms.
//! - [`dns`]          – async DNS TXT lookup for DKIM public keys.
//! - [`key`]          – key types wrapping `ring` primitives.
//! - [`sign`]         – signing a message with a private key.
//! - [`verify`]       – verifying `DKIM-Signature` headers.

pub mod canonicalize;
pub mod dns;
pub mod key;
pub mod sign;
pub mod signature;
pub mod tag_list;
pub mod verify;

pub use sign::{SignRequest, Signer};
pub use signature::{Algorithm, Canonicalization, DkimSignature};
pub use verify::{VerificationResult, VerificationStatus, Verifier};

use thiserror::Error;

/// Errors that can arise during DKIM signing or verification.
#[derive(Debug, Error)]
pub enum Error {
    /// A tag-list could not be parsed.
    #[error("tag-list parse error: {0}")]
    TagListParse(String),

    /// A required tag was missing from a DKIM-Signature header.
    #[error("missing required tag: {0}")]
    MissingTag(&'static str),

    /// A tag value was present but had an invalid format.
    #[error("invalid tag value for {tag}: {reason}")]
    InvalidTag {
        /// The tag name.
        tag: &'static str,
        /// Why it was invalid.
        reason: String,
    },

    /// A DNS lookup for a DKIM public key failed transiently.
    ///
    /// The verifier MUST treat this as `temperror` (RFC 6376 §3.9).
    #[error("DNS lookup failed (transient): {0}")]
    DnsTempError(String),

    /// A DNS lookup returned NXDOMAIN or no TXT record.
    ///
    /// The verifier MUST treat this as `permerror` (RFC 6376 §3.9).
    #[error("DNS lookup failed (permanent): {0}")]
    DnsPermError(String),

    /// The public key could not be decoded from the DNS TXT record.
    #[error("key decode error: {0}")]
    KeyDecode(String),

    /// Cryptographic signature verification failed.
    #[error("signature mismatch")]
    SignatureMismatch,

    /// The signature has expired (`x=` tag in the past).
    #[error("signature expired at {0}")]
    Expired(u64),

    /// An I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// An error from the email-primitives layer.
    #[error("email primitive error: {0}")]
    Primitive(#[from] email_primitives::Error),
}

/// Convenience `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;
