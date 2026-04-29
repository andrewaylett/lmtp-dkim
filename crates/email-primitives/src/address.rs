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
    pub fn parse(_input: &str) -> Result<Self> {
        todo!("winnow parser for RFC 5322 addr-spec: dot-atom / quoted-string \"@\" domain")
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
    /// # Errors
    ///
    /// Returns [`Error::InvalidDomain`] if the domain is syntactically
    /// invalid.
    pub fn parse(_input: &str) -> Result<Self> {
        todo!("validate label structure per RFC 1123 §2.1; lowercase normalise")
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
        let _ = other;
        todo!("check other == self or other ends with .{self}")
    }
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
