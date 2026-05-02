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

use std::collections::HashMap;

use email_primitives::{Header, Headers};

use crate::signature::CanonicalizationAlgorithm;

/// Canonicalize a header field for inclusion in the signing hash.
///
/// `header_algo` is the algorithm to apply (simple or relaxed).
///
/// Returns the byte string that is included in the `data-to-sign` block.
/// Multiple headers are concatenated in the order given by `h=`.
///
/// For the DKIM-Signature header itself, the value passed to this function
/// must have `b=` set to empty (RFC 6376 §3.7 step 5).
#[must_use]
pub fn canonicalize_header(header: &Header, algo: CanonicalizationAlgorithm) -> Vec<u8> {
    match algo {
        // RFC 6376 §3.4.1: simple — use wire form verbatim (name:value\r\n)
        CanonicalizationAlgorithm::Simple => header.to_wire().into_bytes(),

        // RFC 6376 §3.4.2: relaxed — lowercase name, unfold+normalize value
        CanonicalizationAlgorithm::Relaxed => {
            let name = header.name.to_lowercase();
            let unfolded = header.value.unfold();
            // Collapse all runs of SP/HTAB to a single SP
            let mut normalized = String::with_capacity(unfolded.len());
            let mut in_wsp = false;
            for c in unfolded.chars() {
                if c == ' ' || c == '\t' {
                    if !in_wsp {
                        normalized.push(' ');
                        in_wsp = true;
                    }
                } else {
                    in_wsp = false;
                    normalized.push(c);
                }
            }
            // Strip WSP before and after the colon (leading/trailing from value)
            let normalized = normalized.trim();
            format!("{name}:{normalized}\r\n").into_bytes()
        }
    }
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
#[must_use]
pub fn canonicalize_headers(
    headers: &Headers,
    signed_names: &[String],
    algo: CanonicalizationAlgorithm,
) -> Vec<u8> {
    // Build a pool: lowercase name → VecDeque of &Header (top-to-bottom order).
    // pop_back gives the bottommost occurrence first (RFC 6376 §5.4.2).
    let mut pool: HashMap<String, std::collections::VecDeque<&Header>> = HashMap::new();
    for h in headers.iter() {
        pool.entry(h.name.to_lowercase()).or_default().push_back(h);
    }

    let mut out = Vec::new();
    for name in signed_names {
        let lc = name.to_ascii_lowercase();
        if let Some(h) = pool
            .get_mut(&lc)
            .and_then(std::collections::VecDeque::pop_back)
        {
            out.extend_from_slice(&canonicalize_header(h, algo));
        }
        // If name absent, include nothing (RFC 6376 §5.4.2)
    }
    out
}

/// Canonicalize the message body.
///
/// `limit` is the `l=` body length tag: if `Some(n)`, only the first `n` bytes
/// of the canonicalized output are hashed. If `None`, the entire body is used.
///
/// Returns the canonicalized body bytes (possibly truncated to `limit`).
#[must_use]
pub fn canonicalize_body(
    body: &[u8],
    algo: CanonicalizationAlgorithm,
    limit: Option<u64>,
) -> Vec<u8> {
    let result = match algo {
        CanonicalizationAlgorithm::Simple => canonicalize_body_simple(body),
        CanonicalizationAlgorithm::Relaxed => canonicalize_body_relaxed(body),
    };
    apply_limit(result, limit)
}

fn canonicalize_body_simple(body: &[u8]) -> Vec<u8> {
    // RFC 6376 §3.4.3: strip trailing CRLFs, append one CRLF.
    let mut out = body;
    while out.ends_with(b"\r\n") {
        out = &out[..out.len() - 2];
    }
    let mut result = out.to_vec();
    result.extend_from_slice(b"\r\n");
    result
}

fn canonicalize_body_relaxed(body: &[u8]) -> Vec<u8> {
    // RFC 6376 §3.4.4: normalize each line, strip trailing empty lines, append CRLF.
    // Split on CRLF boundaries.
    let mut lines: Vec<&[u8]> = body.split(|&b| b == b'\n').collect();
    // Remove the trailing CR left by split (each element ends with '\r' except the last).
    // Actually split on b'\n' leaves each line with a possible trailing b'\r'.
    // Drop a final empty element produced by a trailing "\r\n" (common case).
    if lines.last() == Some(&b"".as_slice()) {
        lines.pop();
    }

    let mut processed: Vec<Vec<u8>> = lines
        .into_iter()
        .map(|line| {
            // Strip trailing CR from the line (from CRLF split)
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            // Collapse internal WSP and strip trailing WSP
            let mut out: Vec<u8> = Vec::with_capacity(line.len());
            let mut in_wsp = false;
            for &b in line {
                if b == b' ' || b == b'\t' {
                    if !in_wsp {
                        out.push(b' ');
                        in_wsp = true;
                    }
                } else {
                    in_wsp = false;
                    out.push(b);
                }
            }
            // Strip trailing WSP
            while out.last() == Some(&b' ') || out.last() == Some(&b'\t') {
                out.pop();
            }
            out
        })
        .collect();

    // Drop trailing empty lines (RFC 6376 §3.4.4)
    while processed.last() == Some(&vec![]) {
        processed.pop();
    }

    let mut result = Vec::new();
    for line in &processed {
        result.extend_from_slice(line);
        result.extend_from_slice(b"\r\n");
    }
    // If body is empty after processing, treat as single CRLF
    if result.is_empty() {
        result.extend_from_slice(b"\r\n");
    }
    result
}

fn apply_limit(mut data: Vec<u8>, limit: Option<u64>) -> Vec<u8> {
    if let Some(n) = limit {
        data.truncate(usize::try_from(n).unwrap_or(usize::MAX));
    }
    data
}

/// Compute the SHA-256 hash of the canonicalized body and return it as raw bytes.
///
/// This is the `bh=` value (before base64 encoding).
#[must_use]
pub fn body_hash(canonicalized_body: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, canonicalized_body);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use email_primitives::{Header, HeaderName, HeaderValue, Headers};

    use super::{body_hash, canonicalize_body, canonicalize_header, canonicalize_headers};
    use crate::signature::CanonicalizationAlgorithm;

    fn header(name: &str, value: &str) -> Header {
        Header::new(
            HeaderName::new(name).expect("valid name"),
            HeaderValue::new(value).expect("valid value"),
        )
    }

    // ── Header canonicalization ──────────────────────────────────────────────

    /// RFC 6376 §3.4.1: simple preserves the wire form exactly.
    #[test]
    fn header_simple_preserves_wire() {
        let h = header("Subject", " Hello");
        let out = canonicalize_header(&h, CanonicalizationAlgorithm::Simple);
        assert_eq!(out, b"Subject: Hello\r\n");
    }

    /// RFC 6376 §3.4.2: relaxed lowercases the header name.
    #[test]
    fn header_relaxed_lowercases_name() {
        let h = header("Subject", " Hello");
        let out = canonicalize_header(&h, CanonicalizationAlgorithm::Relaxed);
        assert_eq!(out, b"subject:Hello\r\n");
    }

    /// RFC 6376 §3.4.2: relaxed collapses multiple WSP to a single SP.
    #[test]
    fn header_relaxed_collapses_wsp() {
        let h = header("Subject", "  Hello   World");
        let out = canonicalize_header(&h, CanonicalizationAlgorithm::Relaxed);
        assert_eq!(out, b"subject:Hello World\r\n");
    }

    /// RFC 6376 §3.4.2: relaxed unfolds continuation lines.
    #[test]
    fn header_relaxed_unfolds() {
        // Folded value: " Hello\r\n World" — HeaderValue allows this
        let h = header("Subject", " Hello\r\n World");
        let out = canonicalize_header(&h, CanonicalizationAlgorithm::Relaxed);
        assert_eq!(out, b"subject:Hello World\r\n");
    }

    // ── Headers (multi-header) canonicalization ──────────────────────────────

    /// RFC 6376 §5.4.2: headers are consumed bottom-up for repeated names.
    #[test]
    fn headers_bottom_up_selection() {
        let mut hdrs = Headers::new();
        hdrs.push(header("From", " alice@example.com"));
        hdrs.push(header("From", " bob@example.com"));

        let names = vec!["from".to_owned(), "from".to_owned()];
        let out = canonicalize_headers(&hdrs, &names, CanonicalizationAlgorithm::Relaxed);

        let s = String::from_utf8(out).expect("utf8");
        // First selection must be the bottommost (bob), second is alice
        assert!(
            s.starts_with("from:bob@example.com\r\n"),
            "expected bob first, got: {s:?}"
        );
        assert!(
            s.contains("from:alice@example.com\r\n"),
            "expected alice second"
        );
    }

    /// RFC 6376 §5.4.2: missing header names produce no output.
    #[test]
    fn headers_missing_name_skipped() {
        let mut hdrs = Headers::new();
        hdrs.push(header("Subject", " test"));

        let names = vec!["x-missing".to_owned()];
        let out = canonicalize_headers(&hdrs, &names, CanonicalizationAlgorithm::Simple);
        assert!(out.is_empty());
    }

    // ── Body canonicalization ────────────────────────────────────────────────

    /// RFC 6376 §3.4.3: simple strips trailing CRLFs and appends one.
    #[test]
    fn body_simple_strips_trailing_crlf() {
        let out = canonicalize_body(b"line\r\n\r\n\r\n", CanonicalizationAlgorithm::Simple, None);
        assert_eq!(out, b"line\r\n");
    }

    /// RFC 6376 §3.4.3: empty body becomes a single CRLF.
    #[test]
    fn body_simple_empty_body() {
        let out = canonicalize_body(b"", CanonicalizationAlgorithm::Simple, None);
        assert_eq!(out, b"\r\n");
    }

    /// RFC 6376 §3.4.3: single CRLF body is preserved as-is.
    #[test]
    fn body_simple_single_crlf() {
        let out = canonicalize_body(b"\r\n", CanonicalizationAlgorithm::Simple, None);
        assert_eq!(out, b"\r\n");
    }

    /// RFC 6376 §3.4.4: relaxed compresses internal WSP to single SP.
    #[test]
    fn body_relaxed_compresses_wsp() {
        let out = canonicalize_body(b"line  two\r\n", CanonicalizationAlgorithm::Relaxed, None);
        assert_eq!(out, b"line two\r\n");
    }

    /// RFC 6376 §3.4.4: relaxed strips trailing WSP from each line.
    #[test]
    fn body_relaxed_strips_trailing_wsp() {
        let out = canonicalize_body(b"line   \r\n", CanonicalizationAlgorithm::Relaxed, None);
        assert_eq!(out, b"line\r\n");
    }

    /// RFC 6376 §3.4.4: relaxed strips trailing empty lines.
    #[test]
    fn body_relaxed_strips_trailing_empty_lines() {
        let out = canonicalize_body(b"line\r\n\r\n", CanonicalizationAlgorithm::Relaxed, None);
        assert_eq!(out, b"line\r\n");
    }

    /// RFC 6376 §3.4.4: empty body becomes a single CRLF.
    #[test]
    fn body_relaxed_empty_body() {
        let out = canonicalize_body(b"", CanonicalizationAlgorithm::Relaxed, None);
        assert_eq!(out, b"\r\n");
    }

    /// `l=` tag truncates the canonicalized body to the given byte count.
    #[test]
    fn body_limit_truncates() {
        let out = canonicalize_body(b"abcdef\r\n", CanonicalizationAlgorithm::Simple, Some(3));
        assert_eq!(out, b"abc");
    }

    /// SHA-256 of `\r\n` matches the known digest.
    #[test]
    fn body_hash_known_value() {
        let h = body_hash(b"\r\n");
        // Known SHA-256 of b"\r\n"
        assert_eq!(
            h,
            [
                0x7e, 0xb7, 0x02, 0x57, 0x59, 0x3d, 0xa0, 0x6f, 0x68, 0x2a, 0x3d, 0xdd, 0xa5, 0x4a,
                0x9d, 0x26, 0x0d, 0x4f, 0xc5, 0x14, 0xf6, 0x45, 0x23, 0x7f, 0x5c, 0xa7, 0x4b, 0x08,
                0xf8, 0xda, 0x61, 0xa6,
            ]
        );
    }
}
