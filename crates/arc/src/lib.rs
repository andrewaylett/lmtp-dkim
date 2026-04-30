//! ARC (Authenticated Received Chain) signing and validation per RFC 8617.
//!
//! # Purpose
//!
//! ARC solves a specific problem with DKIM: when a message passes through an
//! intermediary (e.g. a mailing list server) that modifies the message
//! (changing the `From:` display name, adding a footer, re-wrapping lines),
//! the original DKIM signature becomes invalid. ARC allows the intermediary to
//! record the authentication state it observed and sign that record, so that
//! subsequent receivers can trust the intermediary's assertion.
//!
//! # ARC header fields
//!
//! Each participating intermediary ("ARC Participating Forwarder", APF) adds
//! a set of three header fields, called an **ARC Set**, identified by an
//! instance number `i` starting at 1 and incrementing at each hop:
//!
//! | Header (abbr) | Key tags | Purpose |
//! |---------------|----------|---------|
//! | ARC-Authentication-Results (AAR) | `i=`, `authserv-id=` | Auth results at this hop |
//! | ARC-Message-Signature (AMS) | `i=`, DKIM-Signature tags | Message signature at this hop |
//! | ARC-Seal (AS) | `i=`, `cv=`, algorithm | Seals the full ARC chain |
//!
//! The header ordering requirement (RFC 8617 §5.1): ARC-Authentication-Results
//! MUST be added before ARC-Message-Signature, which MUST be added before
//! ARC-Seal.
//!
//! # Chain validation (RFC 8617 §6)
//!
//! 1. Collect all `ARC-Seal`, `ARC-Message-Signature`, and
//!    `ARC-Authentication-Results` headers. Group by `i=` into ARC Sets.
//! 2. Verify instance numbers are contiguous from 1 to the highest `i`.
//! 3. Verify the `ARC-Message-Signature` with `i=1` (oldest hop).
//! 4. Verify each `ARC-Seal` in ascending order of `i`.
//! 5. The chain validation result (`cv=`) is:
//!    - `none` – no ARC headers present.
//!    - `pass` – all seals and the oldest AMS verify.
//!    - `fail` – any seal fails, or the oldest AMS fails.
//!
//! The `cv=` tag in each `ARC-Seal` records the chain state **before** this
//! hop signed. The first hop always sets `cv=none`; subsequent hops set
//! `cv=pass` if the chain was passing or `cv=fail` if it was already broken.
//!
//! # Signing (RFC 8617 §5)
//!
//! When an APF receives a message and wants to add ARC:
//!
//! 1. Determine the next instance number `i` (1 plus the highest existing, or 1).
//! 2. Evaluate authentication results: run/collect SPF, DKIM, DMARC, and the
//!    existing ARC chain validation.
//! 3. Add `ARC-Authentication-Results: i=<i>; <authserv-id>; <results>`.
//! 4. Compute and add `ARC-Message-Signature: i=<i>; ...` (like DKIM signing,
//!    but MUST include the new AAR in `h=`).
//! 5. Compute and add `ARC-Seal: i=<i>; cv=<chain-result>; ...`, which covers
//!    all ARC headers from all instances (§5.1.1).
//!
//! # Limits
//!
//! RFC 8617 §5.1.1.3: the maximum instance number is 50. If `i` would exceed
//! 50, the APF MUST NOT add ARC headers.
//!
//! [RFC 8617]: https://www.rfc-editor.org/rfc/rfc8617
//! [RFC 7601]: https://www.rfc-editor.org/rfc/rfc7601
//!
//! # Module layout
//!
//! - [`headers`] – typed representations of ARC-Seal, ARC-Message-Signature,
//!   and ARC-Authentication-Results.
//! - [`auth_results`] – `Authentication-Results` header parsing per RFC 7601.
//! - [`chain`] – chain validation logic.
//! - [`seal`] – signing: construct and add an ARC set.

pub mod auth_results;
pub mod chain;
pub mod headers;
pub mod seal;

pub use chain::{ArcChainResult, ChainValidator};
pub use headers::{ArcMessageSignature, ArcSeal, ArcSet, AuthenticationResults};
pub use seal::{ArcSigner, SealRequest};

use thiserror::Error;

/// Maximum ARC instance number (RFC 8617 §5.1.1.3).
pub const MAX_INSTANCE: u32 = 50;

/// Errors that can arise during ARC processing.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    /// An ARC header field could not be parsed.
    #[error("ARC header parse error: {0}")]
    HeaderParse(String),

    /// An ARC-Seal or ARC-Message-Signature failed to verify.
    #[error("ARC verification failed at i={instance}: {reason}")]
    VerificationFailed {
        /// The instance number where verification failed.
        instance: u32,
        /// Human-readable reason.
        reason: String,
    },

    /// Instance numbers in the ARC headers are not contiguous.
    #[error("ARC instance numbers are not contiguous (found i={found}, expected i={expected})")]
    InstanceGap {
        /// The next expected instance.
        expected: u32,
        /// The next found instance.
        found: u32,
    },

    /// The instance number would exceed the maximum of 50.
    #[error("ARC instance limit exceeded (i={0} > 50)")]
    InstanceLimitExceeded(u32),

    /// A DNS lookup failed.
    #[error("DNS error: {0}")]
    Dns(#[from] dkim::Error),

    /// An error from the email-primitives layer.
    #[error("email primitive error: {0}")]
    Primitive(#[from] email_primitives::Error),
}

/// Convenience `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;
