//! DKIM-Signature header field representation.
//!
//! A `DKIM-Signature` header encodes the signing parameters as a tag-value
//! list. The complete set of tags defined in RFC 6376 §3.5 is:
//!
//! | Tag | Required | Description |
//! |-----|----------|-------------|
//! | `v` | MUST | Version, always `1` |
//! | `a` | MUST | Signing algorithm (`rsa-sha256`, `ed25519-sha256`) |
//! | `b` | MUST | Signature bytes (base64) |
//! | `bh` | MUST | Body hash (base64) |
//! | `d` | MUST | Signing domain (SDID) |
//! | `h` | MUST | Signed header fields (colon-separated) |
//! | `s` | MUST | Selector |
//! | `c` | SHOULD | Canonicalization algorithms (`hdr/body`) |
//! | `i` | MAY | Agent or User Identifier (AUID); defaults to `@<d>` |
//! | `l` | MAY | Body length count (not recommended) |
//! | `q` | MAY | Query methods (default `dns/txt`) |
//! | `t` | SHOULD | Signature timestamp (Unix epoch seconds) |
//! | `x` | MAY | Signature expiry (Unix epoch seconds) |
//! | `z` | MAY | Copied header fields (for debugging) |
//!
//! # Requirement on `From:`
//!
//! Every DKIM-Signature MUST include `From:` in `h=` (RFC 6376 §5.4).
//! The `d=` domain must be the same as or a parent of the `From:` header
//! domain (RFC 6376 §6.1.1 step 8).

use email_primitives::Domain;

#[expect(
    unused_imports,
    reason = "stub: TagList used when parse() is implemented"
)]
use crate::tag_list::TagList;
use crate::{Error, Result};

/// The signing algorithm used in `a=`.
///
/// See RFC 6376 §3.3 and RFC 8463 for the Ed25519 variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// `rsa-sha256` (RFC 6376 §3.3.1). RSA with PKCS#1 v1.5 padding and SHA-256.
    ///
    /// Key size MUST be at least 1024 bits; 2048+ RECOMMENDED (RFC 8301).
    RsaSha256,

    /// `ed25519-sha256` (RFC 8463 §3). Ed25519 with SHA-256 pre-hash.
    ///
    /// Keys are always 256 bits (32 bytes). Faster than RSA and offers
    /// stronger security guarantees.
    Ed25519Sha256,
}

impl Algorithm {
    /// Parse the algorithm tag value string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTag`] for unknown or deprecated algorithms.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "rsa-sha256" => Ok(Self::RsaSha256),
            "ed25519-sha256" => Ok(Self::Ed25519Sha256),
            "rsa-sha1" => Err(Error::InvalidTag {
                tag: "a",
                reason: "rsa-sha1 is deprecated and MUST NOT be used (RFC 8301)".to_owned(),
            }),
            other => Err(Error::InvalidTag {
                tag: "a",
                reason: format!("unknown algorithm: {other:?}"),
            }),
        }
    }

    /// The wire representation for the `a=` tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa-sha256",
            Self::Ed25519Sha256 => "ed25519-sha256",
        }
    }
}

/// The canonicalization algorithm for a single part (header or body).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CanonicalizationAlgorithm {
    /// `simple` – minimal transformation; preserves original casing and
    /// whitespace. Default per RFC 6376 §3.4.
    #[default]
    Simple,
    /// `relaxed` – normalises header field names and whitespace.
    Relaxed,
}

impl CanonicalizationAlgorithm {
    /// Parse `"simple"` or `"relaxed"`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTag`] for unknown algorithm names.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "simple" => Ok(Self::Simple),
            "relaxed" => Ok(Self::Relaxed),
            other => Err(Error::InvalidTag {
                tag: "c",
                reason: format!("unknown canonicalization: {other:?}"),
            }),
        }
    }

    /// The wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Relaxed => "relaxed",
        }
    }
}

/// The `c=` tag: canonicalization algorithms for header and body.
///
/// Encoded as `<header>/<body>`. Defaults to `simple/simple`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Canonicalization {
    /// Algorithm for header fields.
    pub header: CanonicalizationAlgorithm,
    /// Algorithm for the message body.
    pub body: CanonicalizationAlgorithm,
}

impl Canonicalization {
    /// `relaxed/relaxed` – the most common production choice.
    pub const RELAXED_RELAXED: Self = Self {
        header: CanonicalizationAlgorithm::Relaxed,
        body: CanonicalizationAlgorithm::Relaxed,
    };

    /// Parse `"simple/simple"`, `"relaxed/relaxed"`, etc.
    ///
    /// If the body algorithm is absent, it defaults to `simple`
    /// (RFC 6376 §3.5 `c=` tag description).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTag`] if either algorithm name is unknown.
    pub fn parse(s: &str) -> Result<Self> {
        let _ = s;
        todo!("split on '/'; parse each half; default body to simple if absent")
    }

    /// Serialise to `<header>/<body>`.
    #[must_use]
    pub fn as_str(self) -> String {
        format!("{}/{}", self.header.as_str(), self.body.as_str())
    }
}

/// A fully parsed `DKIM-Signature` header value.
///
/// This struct owns the decoded, validated fields. The raw base64 data for
/// `b=` (signature) and `bh=` (body hash) is decoded into byte vectors.
#[derive(Debug, Clone)]
pub struct DkimSignature {
    /// `a=` – signing algorithm.
    pub algorithm: Algorithm,

    /// `b=` – raw signature bytes (decoded from base64).
    pub signature: Vec<u8>,

    /// `bh=` – body hash bytes (decoded from base64).
    pub body_hash: Vec<u8>,

    /// `c=` – canonicalization algorithms (defaults to `simple/simple`).
    pub canonicalization: Canonicalization,

    /// `d=` – SDID (signing domain).
    pub domain: Domain,

    /// `h=` – signed header field names, in the order specified.
    ///
    /// Must include `From:` (RFC 6376 §5.4). Names are compared
    /// case-insensitively. The list may contain duplicate names to sign
    /// multiple occurrences of a header field.
    pub signed_headers: Vec<String>,

    /// `i=` – AUID. Defaults to `"@<d>"` if absent.
    pub auid: Option<String>,

    /// `l=` – body length limit (bytes of canonicalised body to hash).
    ///
    /// If `None`, the entire body is hashed. If `Some`, only the first `l`
    /// bytes are hashed; the verifier MUST treat any mismatch as `neutral`
    /// rather than `fail` since additional content may have been legitimately
    /// appended.
    pub body_length: Option<u64>,

    /// `s=` – selector.
    pub selector: String,

    /// `t=` – signature creation timestamp (Unix seconds). `None` if absent.
    pub timestamp: Option<u64>,

    /// `x=` – signature expiry timestamp (Unix seconds). `None` if absent.
    pub expiry: Option<u64>,
}

impl DkimSignature {
    /// Parse a DKIM-Signature header field **value** (the part after the
    /// colon). Unfolding must be applied before calling this function.
    ///
    /// Validates that all required tags (`v`, `a`, `b`, `bh`, `d`, `h`, `s`)
    /// are present and that `v=1`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingTag`] for absent required tags, or
    /// [`Error::InvalidTag`] for malformed values.
    pub fn parse(_value: &str) -> Result<Self> {
        todo!(
            "TagList::parse(value); extract required tags; \
             base64-decode b and bh; parse algorithm, canonicalization, domain; \
             return Error::MissingTag for absent required tags"
        )
    }

    /// Serialise the signature to a tag-value list string suitable for use as
    /// a `DKIM-Signature:` header value.
    ///
    /// The `b=` tag is included with the actual signature value. Use
    /// [`DkimSignature::to_signing_input`] to obtain the hash input (with `b=`
    /// empty).
    #[must_use]
    pub fn to_tag_list(&self) -> String {
        todo!("emit all tags in canonical order; base64-encode b and bh; fold long lines")
    }

    /// Produce the hash input string for the DKIM-Signature header itself.
    ///
    /// This is the tag-list with `b=` set to empty, as specified in
    /// RFC 6376 §3.7 step 5.
    #[must_use]
    pub fn to_signing_input(&self) -> String {
        todo!("same as to_tag_list but with b= empty")
    }
}
