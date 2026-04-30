//! Typed representations of ARC header fields.
//!
//! ARC introduces three new header field types (RFC 8617 §4):
//!
//! # ARC-Authentication-Results (AAR)
//!
//! Records the authentication results this APF observed. Format is the same
//! as RFC 7601 `Authentication-Results`, with an added `i=` instance tag:
//!
//! ```text
//! ARC-Authentication-Results: i=1; mx.example.org;
//!     dkim=pass header.d=example.com;
//!     spf=pass smtp.mailfrom=example.com
//! ```
//!
//! # ARC-Message-Signature (AMS)
//!
//! A DKIM-like signature over the message as received at this hop. It uses
//! the same tag-value syntax as `DKIM-Signature` with an additional `i=` tag.
//! The `h=` list MUST include the AAR header for this hop.
//!
//! ```text
//! ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;
//!     d=example.com; s=selector; h=arc-authentication-results:from:to;
//!     bh=...; b=...
//! ```
//!
//! # ARC-Seal (AS)
//!
//! Signs the entire ARC chain (all ARC headers from all previous instances
//! plus the new AAR and AMS). Unlike the AMS, the Seal does NOT sign the
//! non-ARC message content; its `h=` is fixed and implicit (RFC 8617 §5.1.1).
//!
//! The `cv=` tag records the chain validity before this hop added its seal.
//!
//! ```text
//! ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=selector;
//!     t=1234567890; b=...
//! ```

use email_primitives::address::Domain;

use crate::auth_results::AuthResultsValue;
use crate::chain::ArcChainResult;
use crate::{Error, Result};

/// The `cv=` tag value in an ARC-Seal, recording the chain state before
/// this hop's seal was added.
///
/// RFC 8617 §5.1.1: a Participating Forwarder that observes `cv=fail` SHOULD
/// still add its own ARC set (to preserve the chain history) but must set
/// `cv=fail` in its own Seal.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainValidation {
    /// `cv=none` – no ARC headers were present before this hop; this is the
    /// first seal in the chain.
    None,
    /// `cv=pass` – the prior chain validated successfully.
    Pass,
    /// `cv=fail` – the prior chain failed to validate.
    Fail,
}

impl ChainValidation {
    /// Parse the `cv=` tag value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HeaderParse`] for unknown `cv=` values.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "none" => Ok(Self::None),
            "pass" => Ok(Self::Pass),
            "fail" => Ok(Self::Fail),
            other => Err(Error::HeaderParse(format!("unknown cv= value: {other:?}"))),
        }
    }

    /// The wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

impl From<ArcChainResult> for ChainValidation {
    fn from(r: ArcChainResult) -> Self {
        match r {
            ArcChainResult::None => Self::None,
            ArcChainResult::Pass => Self::Pass,
            ArcChainResult::Fail => Self::Fail,
        }
    }
}

/// A parsed `ARC-Authentication-Results` header.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct AuthenticationResults {
    /// `i=` – instance number.
    pub instance: u32,
    /// The authentication service identifier (hostname of this APF).
    pub authserv_id: String,
    /// The individual authentication method results.
    pub results: Vec<AuthResultsValue>,
}

impl AuthenticationResults {
    /// Parse from the header field value (after the colon).
    ///
    /// # Errors
    ///
    /// Returns [`Error::HeaderParse`] if the value is malformed.
    pub fn parse(_value: &str) -> Result<Self> {
        todo!(
            "parse 'i=<n>;' prefix; then authserv-id; \
             then semicolon-separated method=result pairs per RFC 7601 §2.2"
        )
    }

    /// Serialise to a header value string (without the `ARC-Authentication-Results:` prefix).
    #[must_use]
    pub fn to_header_value(&self) -> String {
        todo!("i=<n>; <authserv-id>; <results joined by '; '>")
    }
}

/// A parsed `ARC-Message-Signature` header.
///
/// Shares the same tag-value format as `DKIM-Signature` plus `i=`.
/// The signing and verification logic is delegated to the `dkim` crate.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ArcMessageSignature {
    /// `i=` – instance number.
    pub instance: u32,
    /// The embedded DKIM-Signature fields (algorithm, body hash, etc.).
    ///
    /// Parsed using [`dkim::signature::DkimSignature`].
    pub inner: dkim::DkimSignature,
}

impl ArcMessageSignature {
    /// Parse from the header field value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HeaderParse`] if `i=` is missing or invalid, or if
    /// the embedded DKIM-Signature is malformed.
    pub fn parse(_value: &str) -> Result<Self> {
        todo!(
            "extract 'i=<n>;' prefix; pass remainder to DkimSignature::parse; \
             return Error::HeaderParse if i is missing or invalid"
        )
    }

    /// Serialise to a header value string.
    #[must_use]
    pub fn to_header_value(&self) -> String {
        todo!("'i=<n>; ' + inner.to_tag_list()")
    }
}

/// A parsed `ARC-Seal` header.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ArcSeal {
    /// `i=` – instance number.
    pub instance: u32,
    /// `a=` – signing algorithm.
    pub algorithm: dkim::Algorithm,
    /// `cv=` – chain validity before this seal.
    pub chain_validation: ChainValidation,
    /// `d=` – signing domain.
    pub domain: Domain,
    /// `s=` – selector.
    pub selector: String,
    /// `t=` – signature timestamp.
    pub timestamp: Option<u64>,
    /// `b=` – signature bytes (decoded from base64).
    pub signature: Vec<u8>,
}

impl ArcSeal {
    /// Parse from the header field value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HeaderParse`] if required tags are absent or malformed.
    pub fn parse(_value: &str) -> Result<Self> {
        todo!(
            "TagList::parse; extract i, a, cv, d, s, t, b; \
             base64-decode b; validate required tags"
        )
    }

    /// Serialise to a header value string (with the actual signature).
    #[must_use]
    pub fn to_header_value(&self) -> String {
        todo!("emit all tags in canonical order; base64-encode b; fold long lines")
    }

    /// Serialise with `b=` empty, for use as signing input.
    #[must_use]
    pub fn to_signing_input(&self) -> String {
        todo!("same as to_header_value but with b= empty")
    }
}

/// A complete ARC set: the three headers for one instance number.
///
/// A well-formed message with ARC has one [`ArcSet`] per instance number,
/// with contiguous instance numbers starting at 1.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ArcSet {
    /// The instance number (1-based).
    pub instance: u32,
    /// The `ARC-Authentication-Results` for this hop.
    pub auth_results: AuthenticationResults,
    /// The `ARC-Message-Signature` for this hop.
    pub message_signature: ArcMessageSignature,
    /// The `ARC-Seal` for this hop.
    pub seal: ArcSeal,
}

impl ArcSet {
    /// Validate that all three headers have the same `i=` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HeaderParse`] if the instance numbers are inconsistent.
    pub fn validate_instance_consistency(&self) -> Result<()> {
        todo!(
            "check self.auth_results.instance == self.message_signature.instance \
             == self.seal.instance == self.instance"
        )
    }
}
