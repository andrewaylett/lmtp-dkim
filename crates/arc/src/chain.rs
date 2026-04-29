//! ARC chain validation (RFC 8617 §6).
//!
//! # Algorithm
//!
//! Given a message with ARC headers:
//!
//! 1. **Collect** all ARC-Seal (AS), ARC-Message-Signature (AMS), and
//!    ARC-Authentication-Results (AAR) headers.
//!
//! 2. **Group** them into [`ArcSet`]s by instance number.
//!
//! 3. **Check structure**:
//!    - Instance numbers must be contiguous integers starting at 1.
//!    - Each instance must have exactly one of each header type.
//!    - The highest instance's `ARC-Seal` must have `cv=none` iff `i=1`,
//!      or `cv=pass`/`cv=fail` for `i>1`.
//!
//! 4. **Verify the oldest AMS** (`i=1`): this is a DKIM signature over the
//!    original message body and selected headers. If it fails, the chain fails.
//!
//! 5. **Verify each ARC-Seal** in ascending order of `i`:
//!    - The Seal covers all ARC headers from instances 1 through `i`.
//!    - Specifically, the hash input for AS with instance `i` is the
//!      concatenation (bottom-up) of all:
//!      - `ARC-Authentication-Results` from `i=1` through `i=i`
//!      - `ARC-Message-Signature` from `i=1` through `i=i`
//!      - `ARC-Seal` from `i=1` through `i=i-1` (not the current one)
//!      plus the current `ARC-Seal` with `b=` empty.
//!    - The hash input order follows RFC 8617 §5.1.1.
//!
//! 6. **Report** the result:
//!    - `none` if there are no ARC headers.
//!    - `pass` if all verifications succeeded.
//!    - `fail` if any verification failed.
//!
//! # Chain result in Authentication-Results
//!
//! Per RFC 8617 §7.1, the ARC chain result is recorded as:
//! ```text
//! arc=pass header.oldest-pass=1
//! ```

use email_primitives::Message;

use crate::headers::ArcSet;
use crate::Result;

/// The result of validating an ARC chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcChainResult {
    /// No ARC headers were present.
    None,
    /// All seals and the oldest AMS verified successfully.
    Pass,
    /// At least one seal failed, or the oldest AMS failed.
    Fail,
}

impl ArcChainResult {
    /// The `arc=<result>` string for an `Authentication-Results` header.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

/// The output of a successful chain validation.
#[derive(Debug, Clone)]
pub struct ChainValidationOutput {
    /// The overall chain result.
    pub result: ArcChainResult,

    /// The instance number of the oldest ARC-Seal that contributed to `pass`.
    ///
    /// Set to `None` if the result is not `pass`. Used in the
    /// `header.oldest-pass` property of the `Authentication-Results` header
    /// (RFC 8617 §7.1).
    pub oldest_pass: Option<u32>,

    /// The parsed ARC Sets, sorted by instance number ascending.
    pub sets: Vec<ArcSet>,
}

/// Validates the ARC chain of a received message.
pub struct ChainValidator {
    /// DNS resolver for fetching ARC signing keys.
    ///
    /// ARC uses the same DNS key publication mechanism as DKIM
    /// (`<selector>._domainkey.<domain>` TXT records).
    resolver: dkim::dns::DkimResolver,
}

impl ChainValidator {
    /// Construct a validator with the provided DNS resolver.
    pub fn new(resolver: dkim::dns::DkimResolver) -> Self {
        Self { resolver }
    }

    /// Validate the ARC chain in `message`.
    ///
    /// Returns a [`ChainValidationOutput`] describing the result and the
    /// parsed ARC sets.
    ///
    /// # Errors
    ///
    /// Only structural errors (e.g. missing ARC headers in a set, non-
    /// contiguous instance numbers) are returned as `Err`. Cryptographic
    /// failures produce `ArcChainResult::Fail` inside the `Ok` value.
    pub async fn validate(&self, message: &Message) -> Result<ChainValidationOutput> {
        let _ = message;
        todo!(
            "1. collect_arc_sets(message); \
             2. check_structure(&sets); \
             3. verify_oldest_ams(&sets[0], message, &self.resolver); \
             4. for set in &sets: verify_seal(set, &sets, message, &self.resolver); \
             5. compute oldest_pass; \
             6. return ChainValidationOutput"
        )
    }

    /// Collect all ARC headers from a message and group them into [`ArcSet`]s.
    ///
    /// Returns sets sorted by ascending instance number.
    fn collect_arc_sets(_message: &Message) -> Result<Vec<ArcSet>> {
        todo!(
            "scan headers for ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results; \
             parse instance from each; group by instance; \
             return Err if any instance is missing a required header"
        )
    }

    /// Verify the ARC-Message-Signature at instance 1.
    ///
    /// This is a standard DKIM verification (RFC 8617 §6.1 step 3). It covers
    /// the message as it was first received by the ARC chain.
    async fn verify_oldest_ams(
        _set: &ArcSet,
        _message: &Message,
        _resolver: &dkim::dns::DkimResolver,
    ) -> Result<bool> {
        todo!(
            "extract ARC-Message-Signature i=1; \
             treat inner DkimSignature as a DKIM verification; \
             use dkim::Verifier logic; \
             return Ok(true) on pass, Ok(false) on fail"
        )
    }

    /// Verify an individual ARC-Seal.
    ///
    /// The hash input for AS[i] covers, in order (RFC 8617 §5.1.1):
    /// - All ARC-Authentication-Results headers i=1 through i=N (top-down)
    /// - All ARC-Message-Signatures i=1 through i=N (top-down)
    /// - All ARC-Seals i=1 through i=N-1 (top-down, NOT the current seal)
    /// - The current ARC-Seal header with `b=` empty
    async fn verify_seal(
        _seal: &ArcSet,
        _all_sets: &[ArcSet],
        _resolver: &dkim::dns::DkimResolver,
    ) -> Result<bool> {
        todo!(
            "build hash input from ARC headers per RFC 8617 §5.1.1; \
             fetch public key from DNS; \
             verify seal.seal.signature against hash input; \
             return Ok(true/false)"
        )
    }
}

