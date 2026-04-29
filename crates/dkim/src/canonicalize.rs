//! DKIM header and body canonicalization algorithms.
//!
//! RFC 6376 §3.4 defines two canonicalization algorithms, applied
//! independently to headers and body. The algorithm pair is encoded in the
//! `c=` tag as `<header>/<body>`.
//!
//! # Header canonicalization
//!
//! ## `simple` (§3.4.1)
//!
//! The header field is used exactly as it appears in the message, including
//! the name, the colon, the value, and the terminating CRLF. No transformation
//! is applied except that the terminating CRLF is included verbatim. Folding
//! whitespace is preserved.
//!
//! ## `relaxed` (§3.4.2)
//!
//! 1. Lowercase the header field name.
//! 2. Unfold the value (remove CRLF WSP sequences).
//! 3. Convert all sequences of whitespace (SP and HTAB) in the value to a
//!    single SP.
//! 4. Delete all leading and trailing whitespace from the value.
//! 5. Append `: ` (colon space) between the name and the value.
//! 6. Append CRLF.
//!
//! # Body canonicalization
//!
//! ## `simple` (§3.4.3)
//!
//! 1. If the body is empty, treat it as a single `CRLF`.
//! 2. Remove all trailing CRLF sequences at the end.
//! 3. Append a single CRLF.
//!
//! ## `relaxed` (§3.4.4)
//!
//! 1. Ignore all whitespace at the end of each line.
//! 2. Reduce all sequences of WSP within a line to a single SP.
//! 3. Ignore all empty lines at the end of the message body.
//! 4. Append a single CRLF.
//! 5. If the resulting body is empty, treat it as a single `CRLF`.
//!
//! # Hash computation
//!
//! After canonicalization, the body hash is computed as:
//! `bh = BASE64(SHA-256(canonicalized-body))`
//!
//! If the `l=` tag is present, only the first `l` bytes of the canonicalized
//! body are hashed.

use email_primitives::{Header, Headers};

use crate::signature::{Canonicalization, CanonicalizationAlgorithm};

/// Canonicalize a header field for inclusion in the signing hash.
///
/// `header_algo` is the algorithm to apply (simple or relaxed).
///
/// Returns the byte string that is included in the `data-to-sign` block.
/// Multiple headers are concatenated in the order given by `h=`.
///
/// For the DKIM-Signature header itself, the value passed to this function
/// must have `b=` set to empty (RFC 6376 §3.7 step 5).
pub fn canonicalize_header(header: &Header, algo: CanonicalizationAlgorithm) -> Vec<u8> {
    let _ = (header, algo);
    todo!(
        "simple: name + ':' + value + CRLF; \
         relaxed: lowercase(name) + ':' + normalize_wsp(unfold(value)) + CRLF"
    )
}

/// Canonicalize a sequence of header fields for signing.
///
/// `signed_names` is the `h=` tag list. Headers are selected bottom-up: the
/// last match for each name in `signed_names` is consumed, then the second-to-
/// last for a repeated name, and so on (RFC 6376 §5.4.2).
///
/// If a header name in `h=` does not exist in the message, nothing is included
/// for that name (RFC 6376 §5.4.2, note at end). This is intentional: it
/// prevents an attacker from adding a header that was covered by the signature.
///
/// Returns the concatenated canonical form of all selected headers.
pub fn canonicalize_headers(
    headers: &Headers,
    signed_names: &[String],
    algo: CanonicalizationAlgorithm,
) -> Vec<u8> {
    let _ = (headers, signed_names, algo);
    todo!(
        "for each name in signed_names: find the last unconsumed header with that name; \
         canonicalize it; remove it from the available set for future lookups"
    )
}

/// Canonicalize the message body.
///
/// `limit` is the `l=` body length tag: if `Some(n)`, only the first `n` bytes
/// of the canonicalized output are hashed. If `None`, the entire body is used.
///
/// Returns the canonicalized body bytes (possibly truncated to `limit`).
pub fn canonicalize_body(
    body: &[u8],
    algo: CanonicalizationAlgorithm,
    limit: Option<u64>,
) -> Vec<u8> {
    let _ = (body, algo, limit);
    todo!(
        "simple: strip trailing CRLF sequences; append single CRLF; apply limit; \
         relaxed: compress intra-line WSP; strip trailing WSP per line; \
         strip trailing empty lines; append CRLF; apply limit"
    )
}

/// Compute the SHA-256 hash of the canonicalized body and return it as raw bytes.
///
/// This is the `bh=` value (before base64 encoding).
pub fn body_hash(canonicalized_body: &[u8]) -> [u8; 32] {
    let _ = canonicalized_body;
    todo!("ring::digest::digest(&ring::digest::SHA256, canonicalized_body)")
}
