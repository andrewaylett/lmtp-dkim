//! `Authentication-Results` header parsing per RFC 7601.
//!
//! The `Authentication-Results` header records the outcome of authentication
//! checks performed by a receiving MTA. ARC uses it in two ways:
//!
//! 1. **`ARC-Authentication-Results`**: structured identically to
//!    `Authentication-Results` but with an `i=` prefix. The APF populates
//!    this before sealing.
//!
//! 2. **When building the AAR**: the APF runs or proxies SPF, DKIM, and DMARC
//!    checks, then formats the results into the AAR header.
//!
//! # Format (RFC 7601 §2.2)
//!
//! ```text
//! Authentication-Results: <authserv-id>
//!     [; <method>=<result> [reason=<reason>]
//!      [<property>=<value> ...]]...
//! ```
//!
//! Example:
//! ```text
//! Authentication-Results: mx.example.com;
//!     dkim=pass reason="good signature"
//!         header.d=example.com header.i=@example.com header.s=selector;
//!     spf=pass smtp.mailfrom=example.com;
//!     dmarc=pass policy.dmarc-from=example.com
//! ```
//!
//! # Defined methods relevant to ARC
//!
//! | Method | RFC | Key result properties |
//! |--------|-----|-----------------------|
//! | `dkim` | RFC 6376, RFC 7601 §2.7.1 | `header.d`, `header.s`, `header.i` |
//! | `spf`  | RFC 7208, RFC 7601 §2.7.2 | `smtp.mailfrom`, `smtp.helo` |
//! | `dmarc`| RFC 7489, RFC 7601 §2.7.7 | `header.from` |
//! | `arc`  | RFC 8617, RFC 8617 §7.1   | `header.oldest-pass` |
//!
//! # Trust and replay
//!
//! `Authentication-Results` headers from external sources MUST NOT be trusted
//! (RFC 7601 §7.1). An APF must strip pre-existing `Authentication-Results`
//! headers that it did not itself add before populating the AAR.

/// A single method result within an `Authentication-Results` header.
///
/// Corresponds to one `; method=result ...` clause.
#[derive(Debug, Clone)]
pub struct AuthResultsValue {
    /// The method name, e.g. `"dkim"`, `"spf"`, `"dmarc"`, `"arc"`.
    pub method: String,

    /// The result value, e.g. `"pass"`, `"fail"`, `"none"`, `"temperror"`.
    pub result: String,

    /// Optional `reason=<string>` clause.
    pub reason: Option<String>,

    /// Zero or more property sub-clauses.
    ///
    /// Each is a `ptype.property=value` triple. Common examples:
    /// - `("header", "d", "example.com")` for DKIM
    /// - `("smtp", "mailfrom", "user@example.com")` for SPF
    pub properties: Vec<AuthResultProperty>,
}

/// A single property within a method result.
///
/// Encoded as `<ptype>.<property>=<value>` in the header.
#[derive(Debug, Clone)]
pub struct AuthResultProperty {
    /// The property type, e.g. `"header"`, `"smtp"`, `"policy"`.
    pub ptype: String,
    /// The property name, e.g. `"d"`, `"s"`, `"i"`, `"mailfrom"`.
    pub property: String,
    /// The property value.
    pub value: String,
}

impl AuthResultsValue {
    /// Parse one method result clause from a string.
    pub fn parse(_clause: &str) -> crate::Result<Self> {
        todo!(
            "split on first '='; method name before '=', rest is result + properties; \
             extract optional 'reason=...' and 'ptype.property=value' triples"
        )
    }

    /// Serialise the result clause to a string.
    pub fn to_string(&self) -> String {
        let mut out = format!("{}={}", self.method, self.result);
        if let Some(reason) = &self.reason {
            out.push_str(&format!(" reason={reason:?}"));
        }
        for prop in &self.properties {
            out.push_str(&format!("\n    {}.{}={}", prop.ptype, prop.property, prop.value));
        }
        out
    }
}

impl AuthResultProperty {
    /// Construct a `header.d=<domain>` property (used in DKIM results).
    pub fn header_d(domain: &email_primitives::Domain) -> Self {
        Self {
            ptype: "header".to_owned(),
            property: "d".to_owned(),
            value: domain.as_str().to_owned(),
        }
    }

    /// Construct a `header.s=<selector>` property (used in DKIM results).
    pub fn header_s(selector: &str) -> Self {
        Self {
            ptype: "header".to_owned(),
            property: "s".to_owned(),
            value: selector.to_owned(),
        }
    }

    /// Construct a `header.i=<auid>` property (used in DKIM results).
    pub fn header_i(auid: &str) -> Self {
        Self {
            ptype: "header".to_owned(),
            property: "i".to_owned(),
            value: auid.to_owned(),
        }
    }

    /// Construct a `smtp.mailfrom=<addr>` property (used in SPF results).
    pub fn smtp_mailfrom(addr: &str) -> Self {
        Self {
            ptype: "smtp".to_owned(),
            property: "mailfrom".to_owned(),
            value: addr.to_owned(),
        }
    }

    /// Construct a `header.oldest-pass=<i>` property (used in ARC results).
    ///
    /// Records the oldest instance number that contributed to a `pass` result
    /// (RFC 8617 §7.1).
    pub fn arc_oldest_pass(instance: u32) -> Self {
        Self {
            ptype: "header".to_owned(),
            property: "oldest-pass".to_owned(),
            value: instance.to_string(),
        }
    }
}
