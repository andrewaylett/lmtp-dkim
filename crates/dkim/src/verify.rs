//! DKIM signature verification.
//!
//! # Verification process (RFC 6376 §6)
//!
//! For each `DKIM-Signature` header in the message (top to bottom):
//!
//! 1. Parse the tag-list; reject if syntax is invalid (`permerror`).
//! 2. Validate required tags; check `v=1` (`permerror` if absent/wrong).
//! 3. Validate the `From:` header is covered by `h=` (`permerror`).
//! 4. Check `x=` (expiry): if present and in the past, result is `fail`.
//! 5. Fetch public key from DNS (§3.6.2): `<s>._domainkey.<d>`.
//!    - NXDOMAIN / no TXT → `permerror`.
//!    - Transient error → `temperror`.
//!    - Empty `p=` (revoked) → `permerror`.
//! 6. Canonicalize the body; compute hash; compare to `bh=`.
//!    - Mismatch → `fail`.
//! 7. Canonicalize the signed header fields (§5.4.2, bottom-up).
//! 8. Append the canonical DKIM-Signature header (with `b=` empty).
//! 9. Verify the signature (`b=`) against the public key.
//!    - Mismatch → `fail`.
//! 10. Verify `d=` is the same as or a parent of the `From:` header domain.
//!    - Mismatch → `permerror`.
//!
//! The final DKIM result for the message is the best result across all
//! signatures (preference: `pass` > `neutral` > `fail` > `permerror` >
//! `temperror` > `none`).
//!
//! # Result propagation
//!
//! Per RFC 7601, DKIM results are reported in the `Authentication-Results`
//! header. The [`VerificationResult`] type carries enough information to
//! populate that header, including the `header.i`, `header.d`, and
//! `header.s` result properties.

use email_primitives::Message;

use crate::dns::DkimResolver;
use crate::signature::DkimSignature;
use crate::{Error, Result};

/// The outcome of verifying a single `DKIM-Signature`.
///
/// Maps to the `dkim` method results defined in RFC 7601 §2.7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStatus {
    /// `pass` – the signature validated successfully.
    Pass,
    /// `fail` – the signature was present but cryptographically invalid, or
    /// the body hash did not match.
    Fail,
    /// `neutral` – the signature was present and syntactically valid, but
    /// policy considerations (e.g. `l=` mismatch) prevent asserting pass.
    Neutral,
    /// `temperror` – a transient error (DNS timeout) prevented verification.
    TempError,
    /// `permerror` – a permanent error (malformed signature, revoked key,
    /// NXDOMAIN) means this signature can never be valid.
    PermError,
    /// `none` – no `DKIM-Signature` header was present.
    None,
}

/// The result of verifying one `DKIM-Signature` header.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// The overall outcome.
    pub status: VerificationStatus,

    /// The signing domain (`d=`). `None` if the header could not be parsed.
    pub domain: Option<email_primitives::Domain>,

    /// The selector (`s=`). `None` if the header could not be parsed.
    pub selector: Option<String>,

    /// The AUID (`i=`). `None` if absent or header could not be parsed.
    pub auid: Option<String>,

    /// If the result is not `pass`, a human-readable reason.
    pub reason: Option<String>,
}

impl VerificationResult {
    /// Construct a `none` result (no DKIM-Signature present).
    pub fn none() -> Self {
        Self {
            status: VerificationStatus::None,
            domain: None,
            selector: None,
            auid: None,
            reason: None,
        }
    }

    /// Format for inclusion in an `Authentication-Results` header per RFC 7601.
    ///
    /// Example output:
    /// ```text
    /// dkim=pass header.d=example.com header.s=selector header.i=@example.com
    /// ```
    pub fn to_auth_results_value(&self) -> String {
        todo!(
            "format 'dkim=<status>'; \
             append 'header.d=<domain>' if Some; \
             append 'header.s=<selector>' if Some; \
             append 'header.i=<auid>' if Some; \
             append 'reason=<reason>' if Some"
        )
    }
}

/// Verifies `DKIM-Signature` headers in a message.
pub struct Verifier {
    resolver: DkimResolver,
}

impl Verifier {
    /// Construct a verifier using the provided DNS resolver.
    pub fn new(resolver: DkimResolver) -> Self {
        Self { resolver }
    }

    /// Verify all `DKIM-Signature` headers in `message`.
    ///
    /// Returns a [`VerificationResult`] for each signature, in the order the
    /// `DKIM-Signature` headers appear (top to bottom).
    ///
    /// If the message contains no `DKIM-Signature` headers, returns a
    /// single-element vec containing [`VerificationResult::none()`].
    pub async fn verify(&self, message: &Message) -> Vec<VerificationResult> {
        let _ = message;
        todo!(
            "collect all DKIM-Signature headers; \
             for each: DkimSignature::parse(); \
             fetch public key via self.resolver; \
             canonicalize body and headers; \
             verify bh and b; \
             check expiry and d=/From: relationship; \
             map errors to appropriate VerificationStatus"
        )
    }

    /// Return the best single result across multiple signature results.
    ///
    /// Preference: `pass` > `neutral` > `fail` > `permerror` > `temperror`
    /// > `none`.
    pub fn best_result(results: &[VerificationResult]) -> &VerificationResult {
        let _ = results;
        todo!("iterate and pick highest-precedence status")
    }
}
