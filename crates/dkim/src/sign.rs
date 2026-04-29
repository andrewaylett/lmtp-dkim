//! DKIM message signing.
//!
//! # Signing process (RFC 6376 §5)
//!
//! Given a message and a [`SignRequest`]:
//!
//! 1. Canonicalize the body with the configured body algorithm; compute
//!    `bh = SHA-256(canonicalized-body)`; base64-encode → `bh=` tag.
//!
//! 2. Build the initial DKIM-Signature header with `b=` empty.
//!
//! 3. For each header name in `h=`, select the bottommost unconsumed header
//!    from the message with that name and canonicalize it (header algorithm).
//!    Concatenate all selected canonical header forms.
//!
//! 4. Append the canonical form of the DKIM-Signature header itself (with
//!    `b=` empty and WITHOUT a trailing CRLF on the very last piece per
//!    RFC 6376 §3.7 step 5).
//!
//! 5. Sign the resulting data with the private key.
//!
//! 6. Base64-encode the signature → `b=` tag.
//!
//! 7. Fold the DKIM-Signature header value to line lengths ≤ 78 characters
//!    per RFC 5322 §2.1.1 (using `\r\n\t` folding).
//!
//! 8. Prepend the completed `DKIM-Signature` header to the message.
//!
//! # Header field selection
//!
//! The signer controls which headers to include in `h=`. Recommended
//! (RFC 6376 §5.4.1):
//! - MUST include: `From:`
//! - SHOULD include: `To:`, `Cc:`, `Subject:`, `Date:`, `Reply-To:`,
//!   `Message-ID:`, `Content-Type:`
//! - Consider over-signing: include a header name twice in `h=` even if it
//!   only appears once in the message. This prevents an attacker from
//!   prepending a second occurrence of that header after signing.

use email_primitives::{Domain, Message};

use crate::Result;
use crate::key::PrivateKey;
use crate::signature::Canonicalization;
#[expect(
    unused_imports,
    reason = "stub: DkimSignature used when sign() is implemented"
)]
use crate::signature::DkimSignature;

/// Parameters for a DKIM signing operation.
#[derive(Debug)]
pub struct SignRequest {
    /// `d=` – the signing domain. Must be the same as or a parent of the
    /// `From:` header domain (RFC 6376 §6.1.1 step 8).
    pub domain: Domain,

    /// `s=` – selector.
    pub selector: String,

    /// `c=` – canonicalization algorithms. Defaults to `relaxed/relaxed`.
    pub canonicalization: Canonicalization,

    /// `h=` – header fields to sign.
    ///
    /// Must include `From:`. The names are case-insensitive. Duplicate names
    /// select multiple occurrences (bottom-up).
    pub signed_headers: Vec<String>,

    /// `x=` – optional expiry, as a Unix timestamp. If set, the signature is
    /// invalid after this time.
    pub expiry: Option<u64>,

    /// `l=` – optional body length limit. Not recommended (see module docs).
    pub body_length_limit: Option<u64>,
}

impl SignRequest {
    /// Construct a signing request with sensible defaults.
    ///
    /// Default header list covers the fields recommended by RFC 6376 §5.4.1
    /// plus "over-signing" of `From:` and `To:`.
    #[must_use]
    pub fn new(domain: Domain, selector: impl Into<String>) -> Self {
        Self {
            domain,
            selector: selector.into(),
            canonicalization: Canonicalization::RELAXED_RELAXED,
            signed_headers: vec![
                // Over-sign From and To (listed twice each) so that an attacker
                // cannot prepend a second occurrence after signing.
                "from".to_owned(),
                "from".to_owned(),
                "to".to_owned(),
                "to".to_owned(),
                "cc".to_owned(),
                "subject".to_owned(),
                "date".to_owned(),
                "reply-to".to_owned(),
                "message-id".to_owned(),
                "content-type".to_owned(),
                "mime-version".to_owned(),
            ],
            expiry: None,
            body_length_limit: None,
        }
    }
}

/// A DKIM signer bound to a specific private key.
///
/// Create one [`Signer`] per domain/selector/key combination. The signer is
/// cheaply cloneable and safe to share across threads (`Arc<Signer>`).
pub struct Signer {
    #[expect(dead_code, reason = "stub: used by sign() once implemented")]
    private_key: PrivateKey,
    #[expect(dead_code, reason = "stub: used by sign() once implemented")]
    default_request: SignRequest,
}

impl Signer {
    /// Construct a signer.
    #[must_use]
    pub const fn new(key: PrivateKey, default_request: SignRequest) -> Self {
        Self {
            private_key: key,
            default_request,
        }
    }

    /// Sign a message and return a new [`Message`] with the `DKIM-Signature`
    /// header prepended.
    ///
    /// Uses `default_request` as signing parameters.
    ///
    /// # Errors
    ///
    /// - If the message has no `From:` header.
    /// - If the private key signing operation fails.
    pub fn sign(&self, message: &Message) -> Result<Message> {
        let _ = message;
        todo!(
            "1. canonicalize body; compute bh; \
             2. build DKIM-Signature with b= empty; \
             3. canonicalize selected headers + DKIM-Signature (b= empty); \
             4. self.private_key.sign(data); \
             5. fill in b=; fold header; \
             6. prepend to message headers; return new Message"
        )
    }

    /// Sign a message with a custom [`SignRequest`], overriding the default.
    ///
    /// # Errors
    ///
    /// - If the message has no `From:` header.
    /// - If the private key signing operation fails.
    pub fn sign_with(&self, message: &Message, request: &SignRequest) -> Result<Message> {
        let _ = (message, request);
        todo!("same as sign() but using `request` instead of `self.default_request`")
    }
}
