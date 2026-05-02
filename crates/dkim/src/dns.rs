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

use base64::Engine as _;
use hickory_resolver::TokioResolver;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::rr::RData;

use crate::Error;
use crate::Result;
use crate::key::PublicKey;
use crate::tag_list::TagList;

/// A parsed DKIM DNS record.
#[non_exhaustive]
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
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// `k=rsa` – RSA public key in `SubjectPublicKeyInfo` (SPKI) DER format,
    /// base64-encoded (RFC 6376 §3.6.1).
    Rsa,
    /// `k=ed25519` – Ed25519 public key as 32 raw bytes, base64-encoded
    /// (RFC 8463 §3.1).
    Ed25519,
}

/// Flags from the `t=` DNS tag.
#[non_exhaustive]
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
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::TagListParse`] on syntax errors, or
    /// [`crate::Error::DnsPermError`] if the `p=` key is empty (revoked).
    pub fn parse(txt: &str) -> Result<Self> {
        let tags = TagList::parse(txt)?;

        let version = tags.get("v").map(str::to_owned);
        if let Some(ref v) = version
            && v != "DKIM1"
        {
            return Err(Error::InvalidTag {
                tag: "v",
                reason: format!("expected DKIM1, got {v:?}"),
            });
        }

        let key_type = match tags.get("k").unwrap_or("rsa") {
            "rsa" => KeyType::Rsa,
            "ed25519" => KeyType::Ed25519,
            other => {
                return Err(Error::InvalidTag {
                    tag: "k",
                    reason: format!("unknown key type {other:?}"),
                });
            }
        };

        let p_value = tags.get("p").ok_or(Error::MissingTag("p"))?;
        if p_value.is_empty() {
            return Err(Error::DnsPermError("key revoked (p= is empty)".to_owned()));
        }
        let stripped: String = p_value.chars().filter(|c| !c.is_whitespace()).collect();
        let public_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&stripped)
            .map_err(|e| Error::InvalidTag {
                tag: "p",
                reason: e.to_string(),
            })?;

        let flags = tags
            .get("t")
            .map(|t| {
                t.split(':')
                    .filter_map(|flag| match flag.trim() {
                        "y" => Some(DnsFlag::Testing),
                        "s" => Some(DnsFlag::StrictSubdomains),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            version,
            key_type,
            public_key_bytes,
            flags,
        })
    }

    /// Convert the record into a usable [`PublicKey`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::DnsPermError`] if the key is revoked (empty `p=`).
    pub fn into_public_key(self) -> Result<PublicKey> {
        Ok(match self.key_type {
            KeyType::Rsa => PublicKey::rsa(self.public_key_bytes),
            KeyType::Ed25519 => PublicKey::ed25519(self.public_key_bytes),
        })
    }
}

/// Wraps a `hickory-resolver` for async DKIM public key lookups.
///
/// A single [`DkimResolver`] instance should be shared across the service
/// (e.g. via `Arc`) to benefit from the internal DNS cache.
pub struct DkimResolver {
    inner: TokioResolver,
}

impl DkimResolver {
    /// Construct a new resolver using the system's DNS configuration
    /// (`/etc/resolv.conf` on Linux).
    ///
    /// # Errors
    ///
    /// Returns an error if the system resolver configuration cannot be read.
    pub fn from_system_conf() -> Result<Self> {
        let inner = TokioResolver::builder_tokio()
            .map_err(|e| Error::DnsTempError(e.to_string()))?
            .build()
            .map_err(|e| Error::DnsTempError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Look up the DKIM public key for `<selector>._domainkey.<domain>`.
    ///
    /// Parses the first TXT record found and returns the decoded key.
    ///
    /// # Errors
    ///
    /// - [`crate::Error::DnsTempError`] for transient failures (SERVFAIL, timeout).
    /// - [`crate::Error::DnsPermError`] for NXDOMAIN or empty `p=` (revoked key).
    /// - [`crate::Error::KeyDecode`] if the record is present but the key bytes are
    ///   malformed.
    pub async fn lookup(
        &self,
        selector: &str,
        domain: &email_primitives::Domain,
    ) -> Result<PublicKey> {
        let query_name = domain.dkim_txt_name(selector);
        let lookup = self.inner.txt_lookup(query_name).await.map_err(|e| {
            let msg = e.to_string();
            if matches!(e, NetError::Dns(DnsError::NoRecordsFound(_))) {
                Error::DnsPermError(msg)
            } else {
                Error::DnsTempError(msg)
            }
        })?;

        // Concatenate all character-strings from all TXT answer records
        // (RFC 4408 §3.1.3: multiple strings in one record are concatenated).
        let mut txt = String::new();
        for record in lookup.answers() {
            if let RData::TXT(data) = &record.data {
                for chunk in &data.txt_data {
                    txt.push_str(&String::from_utf8_lossy(chunk));
                }
            }
        }

        if txt.is_empty() {
            return Err(Error::DnsPermError("no TXT record data found".to_owned()));
        }

        DkimDnsRecord::parse(&txt)?.into_public_key()
    }
}

#[cfg(test)]
mod tests {
    use super::{DkimDnsRecord, DnsFlag, KeyType};
    use crate::Error;

    fn ed25519_key_b64() -> &'static str {
        // 32-byte Ed25519 public key, base64-encoded (all zeros for testing)
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }

    /// RFC 6376 §3.6.1: `v=DKIM1` is accepted.
    #[test]
    fn parse_version_ok() {
        let rec = DkimDnsRecord::parse(&format!("v=DKIM1; k=ed25519; p={}", ed25519_key_b64()))
            .expect("valid");
        assert_eq!(rec.version.as_deref(), Some("DKIM1"));
    }

    /// RFC 6376 §3.6.1: wrong `v=` value is rejected.
    #[test]
    fn parse_version_wrong() {
        let err = DkimDnsRecord::parse(&format!("v=DKIM2; k=ed25519; p={}", ed25519_key_b64()))
            .expect_err("bad version");
        assert!(matches!(err, Error::InvalidTag { tag: "v", .. }));
    }

    /// RFC 6376 §3.6.1: absent `v=` is accepted (defaults to DKIM1).
    #[test]
    fn parse_version_absent() {
        let rec = DkimDnsRecord::parse(&format!("k=rsa; p={}", ed25519_key_b64()))
            .expect("valid without v=");
        assert!(rec.version.is_none());
    }

    /// RFC 6376 §3.6.1: `k=rsa` sets RSA key type.
    #[test]
    fn parse_key_type_rsa() {
        let rec = DkimDnsRecord::parse(&format!("k=rsa; p={}", ed25519_key_b64())).expect("valid");
        assert_eq!(rec.key_type, KeyType::Rsa);
    }

    /// RFC 8463 §3.1: `k=ed25519` sets Ed25519 key type.
    #[test]
    fn parse_key_type_ed25519() {
        let rec =
            DkimDnsRecord::parse(&format!("k=ed25519; p={}", ed25519_key_b64())).expect("valid");
        assert_eq!(rec.key_type, KeyType::Ed25519);
    }

    /// RFC 6376 §3.6.1: absent `k=` defaults to RSA.
    #[test]
    fn parse_key_type_default_rsa() {
        let rec =
            DkimDnsRecord::parse(&format!("v=DKIM1; p={}", ed25519_key_b64())).expect("valid");
        assert_eq!(rec.key_type, KeyType::Rsa);
    }

    /// RFC 6376 §3.6.1: unknown key type is rejected.
    #[test]
    fn parse_key_type_unknown() {
        let err =
            DkimDnsRecord::parse(&format!("k=dsa; p={}", ed25519_key_b64())).expect_err("bad k");
        assert!(matches!(err, Error::InvalidTag { tag: "k", .. }));
    }

    /// RFC 6376 §3.6.1: missing `p=` is a permerror.
    #[test]
    fn parse_missing_p() {
        let err = DkimDnsRecord::parse("v=DKIM1; k=rsa").expect_err("no p=");
        assert!(matches!(err, Error::MissingTag("p")));
    }

    /// RFC 6376 §3.6.1: empty `p=` means the key is revoked.
    #[test]
    fn parse_revoked_key() {
        let err = DkimDnsRecord::parse("v=DKIM1; k=rsa; p=").expect_err("revoked");
        assert!(matches!(err, Error::DnsPermError(_)));
    }

    /// RFC 6376 §3.6.1: `t=y:s` sets both flags.
    #[test]
    fn parse_flags_both() {
        let rec = DkimDnsRecord::parse(&format!("v=DKIM1; p={}; t=y:s", ed25519_key_b64()))
            .expect("valid");
        assert!(rec.flags.contains(&DnsFlag::Testing));
        assert!(rec.flags.contains(&DnsFlag::StrictSubdomains));
    }

    /// RFC 6376 §3.6.1: unrecognised flag values are ignored.
    #[test]
    fn parse_flags_unknown_ignored() {
        let rec = DkimDnsRecord::parse(&format!("v=DKIM1; p={}; t=y:z:q", ed25519_key_b64()))
            .expect("valid");
        assert!(rec.flags.contains(&DnsFlag::Testing));
        assert!(!rec.flags.contains(&DnsFlag::StrictSubdomains));
    }

    /// `into_public_key` returns a usable `PublicKey` for a valid RSA record.
    #[test]
    fn into_public_key_rsa() {
        // Minimal valid base64 for the key bytes (arbitrary bytes, no ring parsing)
        let rec = DkimDnsRecord::parse(&format!("k=rsa; p={}", ed25519_key_b64())).expect("valid");
        // PublicKey::rsa accepts any bytes; it only fails at verify time
        let _ = rec.into_public_key().expect("should build PublicKey::Rsa");
    }

    /// `into_public_key` returns a usable `PublicKey` for an Ed25519 record.
    #[test]
    fn into_public_key_ed25519() {
        let rec =
            DkimDnsRecord::parse(&format!("k=ed25519; p={}", ed25519_key_b64())).expect("valid");
        let _ = rec
            .into_public_key()
            .expect("should build PublicKey::Ed25519");
    }
}
