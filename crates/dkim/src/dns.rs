//! Async DNS lookup for DKIM public keys.
//!
//! DKIM public keys are published as DNS TXT records at:
//! ```text
//! <selector>._domainkey.<domain>
//! ```
//! (RFC 6376 §3.6.2.1).
//!
//! # TXT record format
//!
//! The TXT record is a tag-value list (same syntax as `DKIM-Signature`).
//! Defined tags (RFC 6376 §3.6.1):
//!
//! | Tag | Required | Description |
//! |-----|----------|-------------|
//! | `v` | RECOMMENDED | Version; if present must be `DKIM1` |
//! | `k` | MAY | Key type: `rsa` (default) or `ed25519` (RFC 8463) |
//! | `p` | MUST | Public key data (base64, empty string = key revoked) |
//! | `n` | MAY | Human-readable notes |
//! | `s` | MAY | Service type: `*` (default) or `email` |
//! | `t` | MAY | Flags: `y` = testing mode, `s` = no subdomain AUID |
//!
//! # Error handling
//!
//! Per RFC 6376 §3.9, DKIM results must distinguish:
//! - `temperror`: transient DNS failure (SERVFAIL, timeout). The message
//!   should be temporarily rejected or deferred.
//! - `permerror`: permanent failure (NXDOMAIN, no TXT record, malformed
//!   record). The signature should be treated as if it does not exist.
//!
//! # Caching
//!
//! `hickory-resolver` honours the TTL from DNS responses. For long-running
//! services, we wrap the resolver in [`DkimResolver`] which uses the
//! `hickory-resolver` internal cache. This avoids repeated DNS lookups for
//! the same key within its TTL window.

use hickory_resolver::TokioAsyncResolver;

use crate::key::PublicKey;
use crate::{Error, Result};

/// A parsed DKIM DNS record.
#[derive(Debug, Clone)]
pub struct DkimDnsRecord {
    /// `v=` – version. If present must be `DKIM1`; if absent, assume `DKIM1`.
    pub version: Option<String>,

    /// `k=` – key type. Defaults to `rsa` if absent.
    pub key_type: KeyType,

    /// `p=` – the raw public key bytes (decoded from base64).
    ///
    /// An empty value means the key has been revoked. Any signature using a
    /// revoked key MUST be treated as a `permerror` (RFC 6376 §3.6.1).
    pub public_key_bytes: Vec<u8>,

    /// `t=` – flags.
    pub flags: Vec<DnsFlag>,
}

/// Key type from the `k=` DNS tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// `k=rsa` – RSA public key in SubjectPublicKeyInfo (SPKI) DER format,
    /// base64-encoded (RFC 6376 §3.6.1).
    Rsa,
    /// `k=ed25519` – Ed25519 public key as 32 raw bytes, base64-encoded
    /// (RFC 8463 §3.1).
    Ed25519,
}

/// Flags from the `t=` DNS tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsFlag {
    /// `y` – the domain is in testing mode. Verifiers SHOULD NOT treat test
    /// signatures differently, but the flag may be used for monitoring.
    Testing,
    /// `s` – the signing domain (`d=`) must exactly match the `From:` domain.
    /// Subdomains of `d=` are NOT permitted as the AUID domain.
    StrictSubdomains,
}

impl DkimDnsRecord {
    /// Parse a DKIM DNS TXT record string.
    pub fn parse(_txt: &str) -> Result<Self> {
        todo!(
            "TagList::parse(txt); extract k, p, v, t; \
             base64-decode p; return permerror if p is empty (revoked)"
        )
    }

    /// Convert the record into a usable [`PublicKey`].
    ///
    /// Returns [`Error::DnsPermError`] if the key is revoked (empty `p=`).
    pub fn into_public_key(self) -> Result<PublicKey> {
        let _ = self;
        todo!("match key_type; decode DER bytes via ring; return PublicKey")
    }
}

/// Wraps a `hickory-resolver` for async DKIM public key lookups.
///
/// A single [`DkimResolver`] instance should be shared across the service
/// (e.g. via `Arc`) to benefit from the internal DNS cache.
pub struct DkimResolver {
    inner: TokioAsyncResolver,
}

impl DkimResolver {
    /// Construct a new resolver using the system's DNS configuration
    /// (`/etc/resolv.conf` on Linux).
    pub async fn from_system_conf() -> Result<Self> {
        todo!("TokioAsyncResolver::from_system_conf(ResolverOpts::default())")
    }

    /// Look up the DKIM public key for `<selector>._domainkey.<domain>`.
    ///
    /// Parses the first TXT record found and returns the decoded key.
    ///
    /// # Errors
    ///
    /// - [`Error::DnsTempError`] for transient failures (SERVFAIL, timeout).
    /// - [`Error::DnsPermError`] for NXDOMAIN or empty `p=` (revoked key).
    /// - [`Error::KeyDecode`] if the record is present but the key bytes are
    ///   malformed.
    pub async fn lookup(
        &self,
        selector: &str,
        domain: &email_primitives::Domain,
    ) -> Result<PublicKey> {
        let query_name = domain.dkim_txt_name(selector);
        let _ = query_name;
        todo!(
            "self.inner.txt_lookup(query_name); \
             concatenate TXT strings (RFC 4408 §3.1.3); \
             DkimDnsRecord::parse(); .into_public_key(); \
             map NoRecordsFound -> DnsPermError, ProtoError -> DnsTempError"
        )
    }
}
