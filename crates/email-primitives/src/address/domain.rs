use crate::{Error, address};

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
    pub fn parse(input: &str) -> crate::Result<Self> {
        if input.is_empty() {
            return Err(Error::InvalidDomain(input.to_owned()));
        }
        // RFC 1123 §2.1: overall max 253 chars.
        if input.len() > 253 {
            return Err(Error::InvalidDomain(input.to_owned()));
        }
        for label in input.split('.') {
            address::validate_label(label).map_err(|()| Error::InvalidDomain(input.to_owned()))?;
        }
        Ok(Self(input.to_ascii_lowercase()))
    }

    /// The domain as a lowercase ASCII string, suitable for DNS queries.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Construct the DKIM DNS query name for a given selector.
    ///
    /// Returns `<selector>._domainkey.<domain>` per RFC 6376 section 3.6.2.1.
    #[must_use]
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
    #[must_use]
    pub fn is_parent_of(&self, other: &Self) -> bool {
        // Both are already lowercase, so direct comparison is correct.
        // The ".{self}" suffix check ensures we match at a label boundary,
        // preventing "ample.com" from being a parent of "example.com".
        other.0 == self.0 || other.0.ends_with(&format!(".{}", self.0))
    }
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for Domain {
    type Error = Error;

    fn try_from(s: &str) -> crate::Result<Self> {
        Self::parse(s)
    }
}
