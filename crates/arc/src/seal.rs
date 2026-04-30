//! ARC sealing: adding a new ARC set to a message.
//!
//! # Overview
//!
//! After validating the existing ARC chain and evaluating authentication
//! results for the current hop, the APF calls [`ArcSigner::seal`] to produce
//! a new [`ArcSet`] and prepend it to the message.
//!
//! # Signing procedure (RFC 8617 §5.1)
//!
//! Given the message as received, existing ARC sets (if any), the current
//! authentication results, and a signing key:
//!
//! 1. Determine `i = max_existing_instance + 1`. If `i > 50`, abort.
//!
//! 2. Compute `cv`:
//!    - `i = 1` → `cv=none`
//!    - `i > 1` and prior chain passed → `cv=pass`
//!    - `i > 1` and prior chain failed → `cv=fail`
//!
//! 3. Construct and add `ARC-Authentication-Results` (AAR):
//!    ```text
//!    ARC-Authentication-Results: i=<i>; <authserv-id>; <results>
//!    ```
//!
//! 4. Compute and add `ARC-Message-Signature` (AMS):
//!    - Sign like a DKIM signature, but the `h=` MUST include the AAR header
//!      added in step 3 as the first entry.
//!    - MUST also include `From:` and any other headers the APF wishes to
//!      cover (RFC 8617 §5.1.1.2).
//!
//! 5. Compute and add `ARC-Seal` (AS):
//!    - Hash input: concatenation of all ARC headers from all instances
//!      (AAR i=1 through i, AMS i=1 through i, AS i=1 through i-1), plus
//!      the new AS with `b=` empty.
//!    - All headers are canonicalized using the **relaxed** algorithm.
//!    - Sign the hash input; fill in `b=`.
//!
//! # Header insertion order
//!
//! The three new headers must be prepended to the message in this order
//! (outermost first, i.e. closest to the top of the message):
//!
//! ```text
//! ARC-Seal: i=N; ...
//! ARC-Message-Signature: i=N; ...
//! ARC-Authentication-Results: i=N; ...
//! <existing headers>
//! ```
//!
//! This order ensures that when the next hop processes the message, reading
//! headers top-to-bottom yields descending instance numbers.

use email_primitives::Message;

use crate::Result;
use crate::auth_results::AuthResultsValue;
use crate::chain::ArcChainResult;
use crate::headers::ArcSet;

/// Parameters for adding an ARC set to a message.
#[non_exhaustive]
#[derive(Debug)]
pub struct SealRequest {
    /// The authentication service identifier (typically the hostname of this
    /// MTA), used in `ARC-Authentication-Results`.
    pub authserv_id: String,

    /// The domain to use for ARC-Seal and ARC-Message-Signature (`d=`).
    pub domain: email_primitives::Domain,

    /// The selector (`s=`) for the signing key.
    pub selector: String,

    /// The authentication results to record in the AAR.
    ///
    /// These should include the DKIM, SPF, DMARC, and (if applicable) prior
    /// ARC chain validation results.
    pub auth_results: Vec<AuthResultsValue>,

    /// Header fields to include in the ARC-Message-Signature `h=` list
    /// (beyond `ARC-Authentication-Results` and `From:`, which are always
    /// included).
    pub extra_signed_headers: Vec<String>,
}

/// Adds ARC headers to a message.
///
/// A single [`ArcSigner`] instance should be reused across messages so that
/// the underlying key material is loaded only once.
pub struct ArcSigner {
    #[expect(dead_code, reason = "stub: used by seal() once implemented")]
    private_key: dkim::key::PrivateKey,
}

impl ArcSigner {
    /// Construct an [`ArcSigner`] from a private key.
    #[must_use]
    pub const fn new(key: dkim::key::PrivateKey) -> Self {
        Self { private_key: key }
    }

    /// Load a private key from a PEM file and construct an [`ArcSigner`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Dkim`] if the PEM file cannot be read or the
    /// key is malformed.
    pub fn from_pem_file(path: &std::path::Path) -> Result<Self> {
        let _ = path;
        todo!("dkim::key::PrivateKey::from_pem_file(path).map(Self::new)")
    }

    /// Add an ARC set to `message` and return the modified message.
    ///
    /// # Steps
    ///
    /// 1. Extract existing ARC sets from `message` to determine `i` and
    ///    the prior chain result.
    /// 2. If `i` would exceed 50, return [`crate::Error::InstanceLimitExceeded`].
    /// 3. Build and prepend the three ARC headers in the correct order.
    ///
    /// The `prior_chain_result` argument should be the output of
    /// [`crate::chain::ChainValidator::validate`] called on the received
    /// message.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InstanceLimitExceeded`] if adding a new set
    /// would set `i > 50` (RFC 8617 §5.1.1.3).
    pub fn seal(
        &self,
        message: &Message,
        prior_chain_result: ArcChainResult,
        request: SealRequest,
    ) -> Result<Message> {
        let _ = (message, prior_chain_result, request);
        todo!(
            "1. find max existing i from message headers; i_new = max + 1; \
             2. check i_new <= 50; \
             3. build AAR header; \
             4. build AMS: sign message + new AAR with h= including arc-authentication-results; \
             5. build AS: hash all ARC headers including new AAR+AMS + AS(b=empty); \
             6. prepend AS, AMS, AAR to message headers (in that order); \
             7. return new Message"
        )
    }

    /// Build the hash input for an `ARC-Seal` at instance `i`.
    ///
    /// Hash input (RFC 8617 §5.1.1, relaxed canonicalization):
    ///
    /// ```text
    /// AAR(i=1) || AMS(i=1) || ... || AAR(i=N) || AMS(i=N)
    ///   || AS(i=1) || AS(i=2) || ... || AS(i=N-1)
    ///   || AS(i=N, b=empty)
    /// ```
    ///
    /// The ordering within each `i` is: AAR, then AMS; seals are appended
    /// after all AAR/AMS pairs. The new seal with empty `b=` is last.
    #[expect(dead_code, reason = "stub: called by seal() once implemented")]
    fn build_seal_hash_input(
        _existing_sets: &[ArcSet],
        _new_aar_header: &str,
        _new_ams_header: &str,
        _new_as_without_b: &str,
    ) -> Vec<u8> {
        todo!("concatenate canonicalized ARC headers per RFC 8617 §5.1.1 ordering")
    }
}
