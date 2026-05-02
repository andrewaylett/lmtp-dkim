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

use base64::Engine as _;
use email_primitives::address::Domain;

use crate::tag_list::TagList;
use crate::{Error, Result};

/// The signing algorithm used in `a=`.
///
/// See RFC 6376 §3.3 and RFC 8463 for the Ed25519 variant.
#[non_exhaustive]
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
#[non_exhaustive]
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
#[expect(clippy::exhaustive_structs, reason = "exhaustive by RFC")]
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
        let (hdr, body) = match s.split_once('/') {
            Some((h, b)) => (h, b),
            None => (s, "simple"),
        };
        Ok(Self {
            header: CanonicalizationAlgorithm::parse(hdr)?,
            body: CanonicalizationAlgorithm::parse(body)?,
        })
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
#[non_exhaustive]
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
    pub fn parse(value: &str) -> Result<Self> {
        let tags = TagList::parse(value)?;

        let v = tags.get("v").ok_or(Error::MissingTag("v"))?;
        if v != "1" {
            return Err(Error::InvalidTag {
                tag: "v",
                reason: format!("expected 1, got {v:?}"),
            });
        }

        let algorithm = Algorithm::parse(tags.get("a").ok_or(Error::MissingTag("a"))?)?;

        // RFC 6376 §3.5: b= and bh= are base64; FWS may appear within the value
        let signature = decode_b64("b", tags.get("b").ok_or(Error::MissingTag("b"))?)?;
        let body_hash = decode_b64("bh", tags.get("bh").ok_or(Error::MissingTag("bh"))?)?;

        let canonicalization = tags
            .get("c")
            .map(Canonicalization::parse)
            .transpose()?
            .unwrap_or_default();

        let domain = Domain::parse(tags.get("d").ok_or(Error::MissingTag("d"))?).map_err(|e| {
            Error::InvalidTag {
                tag: "d",
                reason: e.to_string(),
            }
        })?;

        let signed_headers: Vec<String> = tags
            .get("h")
            .ok_or(Error::MissingTag("h"))?
            .split(':')
            .map(|s| s.trim().to_ascii_lowercase())
            .collect();

        let auid = tags.get("i").map(str::to_owned);

        let body_length = tags.get("l").map(|s| parse_u64("l", s)).transpose()?;

        let selector = tags.get("s").ok_or(Error::MissingTag("s"))?.to_owned();

        let timestamp = tags.get("t").map(|s| parse_u64("t", s)).transpose()?;

        let expiry = tags.get("x").map(|s| parse_u64("x", s)).transpose()?;

        Ok(Self {
            algorithm,
            signature,
            body_hash,
            canonicalization,
            domain,
            signed_headers,
            auid,
            body_length,
            selector,
            timestamp,
            expiry,
        })
    }

    /// Serialise the signature to a tag-value list string suitable for use as
    /// a `DKIM-Signature:` header value.
    ///
    /// The `b=` tag is included with the actual signature value. Use
    /// [`DkimSignature::to_signing_input`] to obtain the hash input (with `b=`
    /// empty). Tags are emitted in the order: `v`, `a`, `bh`, `c`, `d`, `h`,
    /// optional tags, `s`, then `b` last.
    #[must_use]
    pub fn to_tag_list(&self) -> String {
        let b64 = &base64::engine::general_purpose::STANDARD;
        let mut parts = vec![
            "v=1".to_owned(),
            format!("a={}", self.algorithm.as_str()),
            format!("bh={}", b64.encode(&self.body_hash)),
            format!("c={}", self.canonicalization.as_str()),
            format!("d={}", self.domain),
            format!("h={}", self.signed_headers.join(":")),
        ];
        if let Some(ref auid) = self.auid {
            parts.push(format!("i={auid}"));
        }
        if let Some(l) = self.body_length {
            parts.push(format!("l={l}"));
        }
        parts.push(format!("s={}", self.selector));
        if let Some(t) = self.timestamp {
            parts.push(format!("t={t}"));
        }
        if let Some(x) = self.expiry {
            parts.push(format!("x={x}"));
        }
        parts.push(format!("b={}", b64.encode(&self.signature)));
        parts.join("; ")
    }

    /// Produce the hash input string for the DKIM-Signature header itself.
    ///
    /// This is the tag-list with `b=` set to empty, as specified in
    /// RFC 6376 §3.7 step 5.
    #[must_use]
    pub fn to_signing_input(&self) -> String {
        let full = self.to_tag_list();
        // b= is always the last tag; strip its value
        if let Some(pos) = full.rfind("; b=") {
            format!("{}; b=", &full[..pos])
        } else {
            full
        }
    }
}

fn decode_b64(tag: &'static str, value: &str) -> Result<Vec<u8>> {
    let stripped: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(stripped)
        .map_err(|e| Error::InvalidTag {
            tag,
            reason: e.to_string(),
        })
}

fn parse_u64(tag: &'static str, value: &str) -> Result<u64> {
    value.parse::<u64>().map_err(|e| Error::InvalidTag {
        tag,
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, Canonicalization, CanonicalizationAlgorithm, DkimSignature};
    use crate::Error;

    const MINIMAL: &str =
        "v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=default";

    /// RFC 6376 §3.5: `c=` parses both header and body algorithms.
    #[test]
    fn canonicalization_parse_both() {
        let c = Canonicalization::parse("relaxed/simple").expect("valid");
        assert_eq!(c.header, CanonicalizationAlgorithm::Relaxed);
        assert_eq!(c.body, CanonicalizationAlgorithm::Simple);
    }

    /// RFC 6376 §3.5: body algorithm defaults to `simple` when absent from `c=`.
    #[test]
    fn canonicalization_parse_body_default() {
        let c = Canonicalization::parse("relaxed").expect("valid");
        assert_eq!(c.header, CanonicalizationAlgorithm::Relaxed);
        assert_eq!(c.body, CanonicalizationAlgorithm::Simple);
    }

    /// Unknown canonicalization algorithm returns an error.
    #[test]
    fn canonicalization_parse_unknown() {
        Canonicalization::parse("bogus/simple").expect_err("unknown algorithm");
    }

    /// RFC 6376 §3.5: parse a minimal valid DKIM-Signature header value.
    #[test]
    fn dkim_sig_parse_minimal() {
        let sig = DkimSignature::parse(MINIMAL).expect("valid");
        assert_eq!(sig.algorithm, Algorithm::RsaSha256);
        assert_eq!(sig.domain.as_str(), "example.com");
        assert_eq!(sig.selector, "default");
        assert_eq!(sig.signed_headers, vec!["from"]);
        assert_eq!(sig.signature, b"test");
        assert_eq!(sig.body_hash, b"test");
    }

    /// RFC 6376 §3.5: missing required tag returns `MissingTag`.
    #[test]
    fn dkim_sig_parse_missing_required() {
        let err =
            DkimSignature::parse("v=1; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; h=from; s=default")
                .expect_err("missing d=");
        assert!(matches!(err, Error::MissingTag("d")));
    }

    /// `v=` must be exactly `"1"` per RFC 6376 §3.5.
    #[test]
    fn dkim_sig_parse_bad_version() {
        let input = "v=2; a=rsa-sha256; b=dGVzdA==; bh=dGVzdA==; d=example.com; h=from; s=s";
        let err = DkimSignature::parse(input).expect_err("bad version");
        assert!(matches!(err, Error::InvalidTag { tag: "v", .. }));
    }

    /// Invalid base64 in `b=` returns `InvalidTag`.
    #[test]
    fn dkim_sig_parse_bad_base64() {
        let input = "v=1; a=rsa-sha256; b=!!!; bh=dGVzdA==; d=example.com; h=from; s=s";
        let err = DkimSignature::parse(input).expect_err("bad base64");
        assert!(matches!(err, Error::InvalidTag { tag: "b", .. }));
    }

    /// Serialise then re-parse: key fields survive the round-trip.
    #[test]
    fn dkim_sig_round_trip() {
        let sig = DkimSignature::parse(MINIMAL).expect("parse");
        let wire = sig.to_tag_list();
        let sig2 = DkimSignature::parse(&wire).expect("re-parse");
        assert_eq!(sig2.algorithm, sig.algorithm);
        assert_eq!(sig2.domain.as_str(), sig.domain.as_str());
        assert_eq!(sig2.selector, sig.selector);
        assert_eq!(sig2.signature, sig.signature);
        assert_eq!(sig2.body_hash, sig.body_hash);
    }

    /// RFC 6376 §3.7 step 5: `to_signing_input` produces `b=` with empty value.
    #[test]
    fn dkim_sig_to_signing_input() {
        let sig = DkimSignature::parse(MINIMAL).expect("parse");
        let input = sig.to_signing_input();
        assert!(input.ends_with("; b="), "expected b= empty, got: {input:?}");
        assert!(!input.contains("b=dGVzdA"), "b= value must be empty");
    }
}
