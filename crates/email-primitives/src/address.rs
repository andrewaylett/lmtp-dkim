//! Email address types per RFC 5321 and RFC 5322.
//!
//! # Envelope vs message addresses
//!
//! Email uses addresses in two distinct contexts:
//!
//! 1. **Envelope** (RFC 5321): `MAIL FROM:<addr>` and `RCPT TO:<addr>` on the
//!    wire. The reverse-path can be the null path `<>` for bounces.
//! 2. **Headers** (RFC 5322): `From:`, `To:`, `Cc:`, `Reply-To:` etc. may
//!    include a display name: `"Alice Example" <alice@example.com>`.
//!
//! DKIM (RFC 6376 section 3.5) and ARC operate on the **header** `From:`
//! address. Specifically, the `d=` tag in a DKIM-Signature must be the same
//! as or a parent domain of the `From:` header domain (RFC 6376 section 6.1.1,
//! step 8).
//!
//! # Case sensitivity
//!
//! - **Local part**: case-sensitive in principle (RFC 5321 section 2.4),
//!   though receiving systems usually treat it as case-insensitive. We
//!   preserve the original casing.
//! - **Domain**: case-insensitive (RFC 5321 section 2.3.5). We normalise to
//!   lowercase ASCII on construction.
//!
//! # Internationalised domains
//!
//! Domain names used in SMTP must be in ACE/Punycode form when they contain
//! non-ASCII characters (RFC 5321 section 2.3.5; RFC 5891 IDNA 2008).
//! Conversion from Unicode to Punycode is outside the scope of this crate.

use winnow::{
    ModalResult, Parser,
    combinator::alt,
    error::{ContextError, ErrMode},
    token::{literal, one_of, take_while},
};

use crate::{Error, Result};

/// An email address of the form `local-part@domain`.
///
/// Covers `addr-spec` per RFC 5322 section 3.4.1 and the mailbox form used
/// in RFC 5321 SMTP commands. Display names are NOT included here; see the
/// header parsing layer for the full `name-addr` production.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmailAddress {
    local: LocalPart,
    domain: Domain,
}

impl EmailAddress {
    /// Parse an email address.
    ///
    /// Accepts either bare `local@domain` or angle-bracket `<local@domain>`
    /// form. Strips surrounding whitespace and angle brackets before parsing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidAddress`] if the input does not conform to the
    /// `addr-spec` grammar (RFC 5322 section 3.4.1).
    pub fn parse(input: &str) -> Result<Self> {
        // Strip surrounding whitespace and optional angle brackets.
        let s = input.trim();
        let s = s.strip_prefix('<').unwrap_or(s);
        let s = s.strip_suffix('>').unwrap_or(s);
        let s = s.trim();

        // Split on the last '@' (RFC 5322 §3.4.1: local-part "@" domain).
        let at = s
            .rfind('@')
            .ok_or_else(|| Error::InvalidAddress(input.to_owned()))?;
        let local_str = &s[..at];
        let domain_str = &s[at + 1..];

        if local_str.is_empty() || domain_str.is_empty() {
            return Err(Error::InvalidAddress(input.to_owned()));
        }

        let local =
            parse_local_part(local_str).ok_or_else(|| Error::InvalidAddress(input.to_owned()))?;
        let domain =
            Domain::parse(domain_str).map_err(|_| Error::InvalidAddress(input.to_owned()))?;

        Ok(EmailAddress { local, domain })
    }

    /// The local part (the portion to the left of `@`).
    pub fn local(&self) -> &LocalPart {
        &self.local
    }

    /// The domain (the portion to the right of `@`), normalised to lowercase.
    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    /// Borrow as a [`ReversePath`] for use in SMTP/LMTP `MAIL FROM`.
    pub fn as_reverse_path(&self) -> ReversePath<'_> {
        ReversePath::Address(self)
    }
}

impl std::fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// Returns true if `c` is an `atext` character per RFC 5322 §3.2.3.
fn is_atext(c: char) -> bool {
    matches!(
        c,
        'A'..='Z'
        | 'a'..='z'
        | '0'..='9'
        | '!'
        | '#'
        | '$'
        | '%'
        | '&'
        | '\''
        | '*'
        | '+'
        | '-'
        | '/'
        | '='
        | '?'
        | '^'
        | '_'
        | '`'
        | '{'
        | '|'
        | '}'
        | '~'
    )
}

/// Parse a `dot-atom` local-part: `1*atext *("." 1*atext)` (RFC 5322 §3.4.1).
fn dot_atom<'s>(input: &mut &'s str) -> ModalResult<&'s str> {
    // Take chars that are atext or '.', then post-validate the dot rules.
    let result = take_while(1.., |c: char| is_atext(c) || c == '.').parse_next(input)?;
    // RFC 5322 §3.4.1: no leading, trailing, or adjacent dots.
    if result.starts_with('.') || result.ends_with('.') || result.contains("..") {
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    Ok(result)
}

/// Parse a `quoted-string` local-part (RFC 5322 §3.4.1).
///
/// Grammar: `DQUOTE *(qtext / quoted-pair) DQUOTE`
/// - `qtext` = printable ASCII excluding `\` and `"`
/// - `quoted-pair` = `\` followed by any printable ASCII or SP/HTAB
fn quoted_string<'s>(input: &mut &'s str) -> ModalResult<&'s str> {
    let start = *input;
    // Opening quote.
    literal("\"").parse_next(input)?;
    loop {
        match input.chars().next() {
            None | Some('"') => break,
            Some('\\') => {
                // quoted-pair: consume backslash + one more char
                *input = &input[1..];
                one_of(|c: char| c.is_ascii() && (c == ' ' || c == '\t' || c.is_ascii_graphic()))
                    .parse_next(input)?;
            }
            Some(c) if c != '\r' && c != '\n' && c.is_ascii() => {
                *input = &input[c.len_utf8()..];
            }
            _ => {
                return Err(winnow::error::ErrMode::Backtrack(
                    winnow::error::ContextError::new(),
                ));
            }
        }
    }
    // Closing quote.
    literal("\"").parse_next(input)?;
    let consumed = start.len() - input.len();
    Ok(&start[..consumed])
}

/// Parse the local-part of an address (dot-atom or quoted-string).
fn parse_local_part(s: &str) -> Option<LocalPart> {
    let mut input = s;
    let result = alt((dot_atom, quoted_string)).parse_next(&mut input);
    match result {
        Ok(matched) if input.is_empty() && matched == s => Some(LocalPart(s.to_owned())),
        _ => None,
    }
}

/// The local part of an email address (left of `@`).
///
/// Per RFC 5321 section 4.1.2, the local part is either a `dot-atom` or a
/// `quoted-string`. We preserve the original representation including any
/// quoting. Two local parts that compare equal as strings are equal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocalPart(pub(crate) String);

impl LocalPart {
    /// The raw string value, preserving original quoting.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LocalPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A DNS domain name used in email contexts.
///
/// Stored in lowercase ASCII (RFC 5321 section 2.3.5). Must be a valid
/// label-dot sequence per RFC 1123 section 2.1. We do not validate that the
/// domain actually exists in DNS; that is the responsibility of higher-level
/// code.
///
/// # DKIM relevance
///
/// DKIM uses the domain both:
/// - As part of the `From:` address whose domain is checked against `d=`.
/// - Directly in `d=` (SDID) and `s=` (selector) to construct the DNS query:
///   `<selector>._domainkey.<domain>` (RFC 6376 section 3.6.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Domain(pub(crate) String);

impl Domain {
    /// Parse and normalise a domain string to lowercase ASCII.
    ///
    /// Validates label structure per RFC 1123 §2.1:
    /// - Each label: 1–63 chars, `[A-Za-z0-9-]`, no leading or trailing hyphen.
    /// - No empty labels (consecutive dots or trailing dot).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDomain`] if the domain is syntactically
    /// invalid.
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(Error::InvalidDomain(input.to_owned()));
        }
        // RFC 1123 §2.1: overall max 253 chars.
        if input.len() > 253 {
            return Err(Error::InvalidDomain(input.to_owned()));
        }
        for label in input.split('.') {
            validate_label(label).map_err(|_| Error::InvalidDomain(input.to_owned()))?;
        }
        Ok(Domain(input.to_ascii_lowercase()))
    }

    /// The domain as a lowercase ASCII string, suitable for DNS queries.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Construct the DKIM DNS query name for a given selector.
    ///
    /// Returns `<selector>._domainkey.<domain>` per RFC 6376 section 3.6.2.1.
    pub fn dkim_txt_name(&self, selector: &str) -> String {
        format!("{}._domainkey.{}", selector, self.0)
    }

    /// Return true if `other` is the same domain or a strict subdomain of
    /// `self`.
    ///
    /// Used in DKIM verification (RFC 6376 section 6.1.1 step 8): the
    /// SDID (`d=`) must be the same as or a parent of the `From:` domain.
    ///
    /// Examples:
    /// - `"example.com".is_parent_of("example.com")` → `true`
    /// - `"example.com".is_parent_of("sub.example.com")` → `true`
    /// - `"example.com".is_parent_of("other.com")` → `false`
    pub fn is_parent_of(&self, other: &Domain) -> bool {
        // Both are already lowercase, so direct comparison is correct.
        // The ".{self}" suffix check ensures we match at a label boundary,
        // preventing "ample.com" from being a parent of "example.com".
        other.0 == self.0 || other.0.ends_with(&format!(".{}", self.0))
    }
}

/// Validate a single DNS label per RFC 1123 §2.1.
fn validate_label(label: &str) -> std::result::Result<(), ()> {
    if label.is_empty() || label.len() > 63 {
        return Err(());
    }
    let bytes = label.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(());
    }
    if !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(());
    }
    for &b in bytes {
        if !b.is_ascii_alphanumeric() && b != b'-' {
            return Err(());
        }
    }
    Ok(())
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for Domain {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        Domain::parse(s)
    }
}

/// The reverse-path used in `MAIL FROM` (RFC 5321 section 4.1.1.2).
///
/// The reverse-path is either a real address or the null path `<>`, which
/// is used for bounce messages so that bounces cannot themselves bounce
/// (RFC 5321 section 4.5.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReversePath<'a> {
    /// A real sender address.
    Address(&'a EmailAddress),
    /// The null path `<>` for bounces and delivery status notifications.
    Null,
}

impl std::fmt::Display for ReversePath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReversePath::Address(addr) => write!(f, "<{addr}>"),
            ReversePath::Null => f.write_str("<>"),
        }
    }
}

/// Owned version of [`ReversePath`] for storage in session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullPath {
    /// A real sender address.
    Address(EmailAddress),
    /// The null path `<>`.
    Null,
}

impl std::fmt::Display for NullPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NullPath::Address(addr) => write!(f, "<{addr}>"),
            NullPath::Null => f.write_str("<>"),
        }
    }
}

#[cfg(test)]
mod rfc5322_address {
    use super::*;

    /// RFC 5322 §3.4.1: basic dot-atom addr-spec.
    #[test]
    fn parse_simple() {
        let a = EmailAddress::parse("user@example.com").unwrap();
        assert_eq!(a.local().as_str(), "user");
        assert_eq!(a.domain().as_str(), "example.com");
    }

    /// RFC 5322 §3.4.1: quoted-string local part.
    #[test]
    fn parse_quoted_local() {
        let a = EmailAddress::parse("\"user name\"@example.com").unwrap();
        assert_eq!(a.local().as_str(), "\"user name\"");
        assert_eq!(a.domain().as_str(), "example.com");
    }

    /// RFC 5322 §3.4.1: quoted-pair inside quoted local part.
    #[test]
    fn parse_quoted_pair_local() {
        let a = EmailAddress::parse("\"user\\\"quoted\"@example.com").unwrap();
        assert!(a.local().as_str().starts_with('"'));
    }

    /// RFC 5321 §2.4: local-part case is preserved.
    #[test]
    fn local_case_preserved() {
        let a = EmailAddress::parse("UserName@example.com").unwrap();
        assert_eq!(a.local().as_str(), "UserName");
    }

    /// RFC 5322 §3.4.1: all allowed atext characters accepted.
    #[test]
    fn parse_atext_chars() {
        EmailAddress::parse("user+filter@example.com").unwrap();
        EmailAddress::parse("user.name@example.com").unwrap();
        EmailAddress::parse("user_name@example.com").unwrap();
        EmailAddress::parse("user-name@example.com").unwrap();
    }

    /// Angle-bracket form is stripped.
    #[test]
    fn parse_angle_bracket_form() {
        let a = EmailAddress::parse("<user@example.com>").unwrap();
        assert_eq!(a.local().as_str(), "user");
        assert_eq!(a.domain().as_str(), "example.com");
    }

    /// Whitespace around address is stripped.
    #[test]
    fn parse_whitespace_stripped() {
        let a = EmailAddress::parse("  user@example.com  ").unwrap();
        assert_eq!(a.local().as_str(), "user");
    }

    /// RFC 5322 §3.4.1: missing `@` is rejected.
    #[test]
    fn reject_missing_at() {
        assert!(EmailAddress::parse("userexample.com").is_err());
    }

    /// RFC 5322 §3.4.1: adjacent dots in dot-atom rejected.
    #[test]
    fn reject_adjacent_dots() {
        assert!(EmailAddress::parse("us..er@example.com").is_err());
    }

    /// RFC 5322 §3.4.1: leading dot in local part rejected.
    #[test]
    fn reject_leading_dot() {
        assert!(EmailAddress::parse(".user@example.com").is_err());
    }

    /// RFC 5322 §3.4.1: trailing dot in local part rejected.
    #[test]
    fn reject_trailing_dot() {
        assert!(EmailAddress::parse("user.@example.com").is_err());
    }

    /// Empty local part is rejected.
    #[test]
    fn reject_empty_local() {
        assert!(EmailAddress::parse("@example.com").is_err());
    }

    /// Display renders as `local@domain`.
    #[test]
    fn display() {
        let a = EmailAddress::parse("user@example.com").unwrap();
        assert_eq!(a.to_string(), "user@example.com");
    }
}

#[cfg(test)]
mod rfc5321_domain {
    use super::*;

    /// RFC 5321 §2.3.5 + RFC 1123 §2.1: basic domain parse.
    #[test]
    fn parse_simple() {
        let d = Domain::parse("example.com").unwrap();
        assert_eq!(d.as_str(), "example.com");
    }

    /// RFC 5321 §2.3.5: domain normalised to lowercase.
    #[test]
    fn parse_uppercase_lowercased() {
        let d = Domain::parse("EXAMPLE.COM").unwrap();
        assert_eq!(d.as_str(), "example.com");
    }

    /// RFC 5321 §2.3.5: domain address case insensitivity applies to email.
    #[test]
    fn email_domain_lowercased() {
        let a = EmailAddress::parse("user@EXAMPLE.COM").unwrap();
        assert_eq!(a.domain().as_str(), "example.com");
    }

    /// RFC 1123 §2.1: label may start with digit (relaxation of RFC 952).
    #[test]
    fn label_starts_with_digit() {
        Domain::parse("3com.example.com").unwrap();
    }

    /// Single-label domain accepted (e.g. `localhost`).
    #[test]
    fn single_label() {
        let d = Domain::parse("localhost").unwrap();
        assert_eq!(d.as_str(), "localhost");
    }

    /// RFC 1123 §2.1: label must be ≤ 63 chars.
    #[test]
    fn reject_label_too_long() {
        let long_label = "a".repeat(64);
        assert!(Domain::parse(&format!("{}.com", long_label)).is_err());
    }

    /// RFC 1123 §2.1: label cannot start with hyphen.
    #[test]
    fn reject_hyphen_start() {
        assert!(Domain::parse("-bad.example.com").is_err());
    }

    /// RFC 1123 §2.1: label cannot end with hyphen.
    #[test]
    fn reject_hyphen_end() {
        assert!(Domain::parse("bad-.example.com").is_err());
    }

    /// Trailing dot is rejected (we store without trailing dot for DNS construction).
    #[test]
    fn reject_trailing_dot() {
        assert!(Domain::parse("example.com.").is_err());
    }

    /// Empty string is rejected.
    #[test]
    fn reject_empty() {
        assert!(Domain::parse("").is_err());
    }

    /// Empty label from consecutive dots is rejected.
    #[test]
    fn reject_empty_label() {
        assert!(Domain::parse("example..com").is_err());
    }

    /// RFC 6376 §3.6.2.1: dkim_txt_name constructs correct DNS query name.
    #[test]
    fn dkim_txt_name() {
        let d = Domain::parse("example.com").unwrap();
        assert_eq!(
            d.dkim_txt_name("selector"),
            "selector._domainkey.example.com"
        );
    }

    /// RFC 6376 §6.1.1 step 8: exact match is parent of itself.
    #[test]
    fn is_parent_of_self() {
        let d = Domain::parse("example.com").unwrap();
        assert!(d.is_parent_of(&d.clone()));
    }

    /// RFC 6376 §6.1.1 step 8: parent of a subdomain.
    #[test]
    fn is_parent_of_sub() {
        let parent = Domain::parse("example.com").unwrap();
        let child = Domain::parse("sub.example.com").unwrap();
        assert!(parent.is_parent_of(&child));
    }

    /// RFC 6376 §6.1.1 step 8: unrelated domain is not a parent.
    #[test]
    fn not_parent_of_unrelated() {
        let d1 = Domain::parse("example.com").unwrap();
        let d2 = Domain::parse("notexample.com").unwrap();
        assert!(!d1.is_parent_of(&d2));
    }

    /// RFC 6376 §6.1.1 step 8: suffix match must be at a label boundary.
    ///
    /// "ample.com" must NOT be a parent of "example.com".
    #[test]
    fn not_parent_of_partial_label() {
        let partial = Domain::parse("ample.com").unwrap();
        let full = Domain::parse("example.com").unwrap();
        assert!(!partial.is_parent_of(&full));
    }
}
