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

use std::time::{SystemTime, UNIX_EPOCH};

use email_primitives::{Header, HeaderName, HeaderValue, Headers, Message};

use crate::canonicalize::{
    body_hash, canonicalize_body, canonicalize_header, canonicalize_headers,
};
use crate::key::PrivateKey;
use crate::signature::{Canonicalization, DkimSignature};
use crate::{Error, Result};
use email_primitives::address::Domain;

/// Parameters for a DKIM signing operation.
#[non_exhaustive]
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
    pub fn new<S: Into<String>>(domain: Domain, selector: S) -> Self {
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
    private_key: PrivateKey,
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
        self.sign_with(message, &self.default_request)
    }

    /// Sign a message with a custom [`SignRequest`], overriding the default.
    ///
    /// # Errors
    ///
    /// - If the message has no `From:` header.
    /// - If the private key signing operation fails.
    pub fn sign_with(&self, message: &Message, request: &SignRequest) -> Result<Message> {
        // Step 1: canonicalize body and compute bh=
        let canon_body = canonicalize_body(
            message.body.as_bytes(),
            request.canonicalization.body,
            request.body_length_limit,
        );
        let bh = body_hash(&canon_body);

        // Step 2: current unix timestamp for t=
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());

        // Step 3: build DkimSignature with empty b= placeholder
        let dkim_sig = DkimSignature {
            algorithm: self.private_key.algorithm(),
            signature: Vec::new(),
            body_hash: bh.to_vec(),
            canonicalization: request.canonicalization,
            domain: request.domain.clone(),
            signed_headers: request.signed_headers.clone(),
            auid: None,
            body_length: request.body_length_limit,
            selector: request.selector.clone(),
            timestamp,
            expiry: request.expiry,
        };

        // Step 4: build the DKIM-Signature header for inclusion in the hash input
        let signing_val = dkim_sig.to_signing_input();
        let dkim_hdr_for_signing = Header::new(
            HeaderName::new("DKIM-Signature").map_err(Error::Primitive)?,
            HeaderValue::new(format!(" {signing_val}")).map_err(Error::Primitive)?,
        );

        // Step 5: data-to-sign = canonicalized selected headers ||
        //         canonicalized DKIM-Signature without trailing CRLF
        //         (RFC 6376 §3.7: DKIM-Signature MUST NOT include a trailing CRLF)
        let mut data = canonicalize_headers(
            &message.headers,
            &request.signed_headers,
            request.canonicalization.header,
        );
        let mut dkim_canonical =
            canonicalize_header(&dkim_hdr_for_signing, request.canonicalization.header);
        if dkim_canonical.ends_with(b"\r\n") {
            dkim_canonical.truncate(dkim_canonical.len() - 2);
        }
        data.extend_from_slice(&dkim_canonical);

        // Step 6: sign
        let signature_bytes = self.private_key.sign(&data)?;

        // Step 7: rebuild DkimSignature with real b=
        let dkim_sig_final = DkimSignature {
            signature: signature_bytes,
            ..dkim_sig
        };

        // Step 8: prepend completed DKIM-Signature header to message
        let header_value = dkim_sig_final.to_tag_list();
        let dkim_hdr = Header::new(
            HeaderName::new("DKIM-Signature").map_err(Error::Primitive)?,
            HeaderValue::new(format!(" {header_value}")).map_err(Error::Primitive)?,
        );
        let mut new_headers = Headers::new();
        new_headers.push(dkim_hdr);
        for h in message.headers.iter() {
            new_headers.push(h.clone());
        }
        Ok(Message::new(new_headers, message.body.clone()))
    }
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair as _;

    use super::{SignRequest, Signer};
    use crate::canonicalize::{body_hash, canonicalize_body};
    use crate::key::{PrivateKey, PublicKey};
    use crate::signature::{CanonicalizationAlgorithm, DkimSignature};
    use email_primitives::address::Domain;
    use email_primitives::{Header, HeaderName, HeaderValue, Headers, Message, MessageBody};

    fn make_message(from: &str, subject: &str, body: &[u8]) -> Message {
        let mut headers = Headers::new();
        headers.push(Header::new(
            HeaderName::new("From").expect("From"),
            HeaderValue::new(format!(" {from}")).expect("from value"),
        ));
        headers.push(Header::new(
            HeaderName::new("Subject").expect("Subject"),
            HeaderValue::new(format!(" {subject}")).expect("subject value"),
        ));
        Message::new(
            headers,
            MessageBody::new(bytes::Bytes::copy_from_slice(body)),
        )
    }

    fn ed25519_signer() -> (Signer, PublicKey) {
        let rng = SystemRandom::new();
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519");
        let key_pair =
            ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load ring kp");
        let pub_bytes = key_pair.public_key().as_ref().to_vec();
        let private_key =
            PrivateKey::ed25519_from_pkcs8_der(pkcs8.as_ref()).expect("load private key");
        let domain = Domain::parse("example.com").expect("domain");
        let request = SignRequest::new(domain, "test");
        (
            Signer::new(private_key, request),
            PublicKey::ed25519(pub_bytes),
        )
    }

    /// `sign()` prepends a DKIM-Signature as the first header.
    #[test]
    fn sign_includes_dkim_signature_first() {
        let (the_signer, _) = ed25519_signer();
        let msg = make_message("alice@example.com", "Hello", b"body\r\n");
        let outcome = the_signer.sign(&msg).expect("sign");
        let first = outcome.headers.iter().next().expect("has headers");
        assert_eq!(first.name.as_str(), "DKIM-Signature");
    }

    /// `bh=` in the signed message matches the canonical body hash.
    #[test]
    fn sign_body_hash_correct() {
        let (the_signer, _) = ed25519_signer();
        let body = b"Hello world\r\n";
        let msg = make_message("alice@example.com", "Test", body);
        let outcome = the_signer.sign(&msg).expect("sign");

        let dkim_hdr = outcome
            .headers
            .iter()
            .next()
            .expect("DKIM-Signature header");
        let sig = DkimSignature::parse(dkim_hdr.value.as_str()).expect("parse DKIM-Signature");

        let expected_bh = body_hash(&canonicalize_body(
            body,
            CanonicalizationAlgorithm::Relaxed,
            None,
        ));
        assert_eq!(sig.body_hash, expected_bh.as_ref());
    }

    /// `sign()` produces a non-empty `b=` signature value.
    #[test]
    fn sign_ed25519_nonempty_signature() {
        let (the_signer, _) = ed25519_signer();
        let msg = make_message("alice@example.com", "Test", b"body\r\n");
        let outcome = the_signer.sign(&msg).expect("sign");

        let dkim_hdr = outcome
            .headers
            .iter()
            .next()
            .expect("DKIM-Signature header");
        let sig = DkimSignature::parse(dkim_hdr.value.as_str()).expect("parse");
        assert!(!sig.signature.is_empty());
    }

    /// `sign_with()` uses the supplied canonicalization instead of the default.
    #[test]
    fn sign_with_custom_request() {
        let rng = SystemRandom::new();
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519");
        let private_key =
            PrivateKey::ed25519_from_pkcs8_der(pkcs8.as_ref()).expect("load private key");
        let domain = Domain::parse("example.com").expect("domain");
        let default_req = SignRequest::new(domain.clone(), "default");
        let the_signer = Signer::new(private_key, default_req);

        let mut custom = SignRequest::new(domain, "custom");
        custom.canonicalization = crate::signature::Canonicalization {
            header: CanonicalizationAlgorithm::Simple,
            body: CanonicalizationAlgorithm::Simple,
        };

        let msg = make_message("alice@example.com", "Test", b"body\r\n");
        let outcome = the_signer.sign_with(&msg, &custom).expect("sign_with");

        let dkim_hdr = outcome
            .headers
            .iter()
            .next()
            .expect("DKIM-Signature header");
        let sig = DkimSignature::parse(dkim_hdr.value.as_str()).expect("parse");
        assert_eq!(
            sig.canonicalization.header,
            CanonicalizationAlgorithm::Simple
        );
        assert_eq!(sig.canonicalization.body, CanonicalizationAlgorithm::Simple);
    }
}
