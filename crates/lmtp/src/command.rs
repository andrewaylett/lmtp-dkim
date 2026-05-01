//! LMTP client command types.
//!
//! LMTP reuses the SMTP command set (RFC 5321) with one substitution:
//! `LHLO` replaces `EHLO`/`HELO`. The `HELO` command is explicitly
//! disallowed in LMTP (RFC 2033 section 4.1).
//!
//! # Commands
//!
//! | Command | RFC ref | Description |
//! |---------|---------|-------------|
//! | `LHLO`  | RFC 2033 §4.1 | Opening greeting, replaces EHLO |
//! | `MAIL`  | RFC 5321 §4.1.1.2 | Begin transaction, set reverse-path |
//! | `RCPT`  | RFC 5321 §4.1.1.3 | Add a recipient |
//! | `DATA`  | RFC 5321 §4.1.1.4 | Begin message transfer |
//! | `RSET`  | RFC 5321 §4.1.1.5 | Abort current transaction |
//! | `NOOP`  | RFC 5321 §4.1.1.9 | No-op, keep connection alive |
//! | `VRFY`  | RFC 5321 §4.1.1.6 | Verify an address (may be stubbed) |
//! | `QUIT`  | RFC 5321 §4.1.1.10 | Close connection |
//!
//! # Parameters
//!
//! `MAIL FROM` and `RCPT TO` accept optional ESMTP parameters after the
//! address (RFC 5321 section 4.1.2). Parameters are key=value pairs or bare
//! keywords. Recognised parameters include `SIZE=<n>` and `BODY=8BITMIME`.

use crate::{Error, Result};
use email_primitives::EmailAddress;
use email_primitives::address::Domain;
use email_primitives::address::OwnedReversePath;

/// A parsed LMTP client command.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `LHLO <domain>`
    ///
    /// The client identifies itself with its domain. The server responds with
    /// its hostname and a list of supported extensions, one per line, using
    /// `250-` continuation lines and a final `250 ` line.
    Lhlo {
        /// The domain or address literal the client claims to be.
        client_domain: Domain,
    },

    /// `MAIL FROM:<reverse-path> [SP mail-parameters]`
    ///
    /// Begins a new mail transaction. The reverse-path is where delivery
    /// failure notifications should be sent; it may be `<>` for bounces.
    ///
    /// Common parameters (RFC 5321 section 4.1.2, RFC 1870, RFC 6152):
    /// - `SIZE=<n>` – estimated message size in bytes.
    /// - `BODY=7BIT | 8BITMIME | BINARYMIME` – message body encoding.
    Mail {
        /// The sender's reverse-path.
        from: OwnedReversePath,
        /// Optional ESMTP mail parameters.
        parameters: Vec<MailParam>,
    },

    /// `RCPT TO:<forward-path> [SP rcpt-parameters]`
    ///
    /// Adds a recipient. Multiple `RCPT TO` commands may be issued before
    /// `DATA`. Each recipient will receive an individual response after `DATA`
    /// is completed (the key LMTP difference from SMTP).
    Rcpt {
        /// The recipient address.
        to: EmailAddress,
        /// Optional ESMTP recipient parameters.
        parameters: Vec<RcptParam>,
    },

    /// `DATA`
    ///
    /// Signals the start of the message transfer. The server responds with
    /// `354` and the client sends the message body terminated by `\r\n.\r\n`.
    /// Dot-stuffing applies: any line beginning with `.` has an extra `.`
    /// prepended by the sender (RFC 5321 section 4.5.2).
    Data,

    /// `RSET`
    ///
    /// Aborts the current transaction and resets the session to the
    /// post-`LHLO` (Greeted) state.
    Rset,

    /// `NOOP [<string>]`
    ///
    /// No operation; the server responds `250 OK`. Useful for keepalive.
    Noop,

    /// `VRFY <string>`
    ///
    /// Asks the server to verify an address. Servers are permitted to return
    /// `252` ("Cannot VRFY user, but will accept message") without actually
    /// verifying (RFC 5321 section 7.3).
    Vrfy {
        /// The address or name to verify.
        query: String,
    },

    /// `QUIT`
    ///
    /// Requests graceful shutdown. The server responds `221` and closes the
    /// connection.
    Quit,
}

impl Command {
    /// Parse a single LMTP command line.
    ///
    /// The input should be a single line without the terminating CRLF.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadCommand`] if the line cannot be parsed as a
    /// valid LMTP command.
    pub fn parse(line: &str) -> Result<Self> {
        let bad = || Error::BadCommand(line.to_owned());

        // Split verb from rest; verb is case-insensitive (RFC 5321 §2.4).
        let (verb, rest) = match line.find(|c: char| c.is_ascii_whitespace()) {
            Some(i) => (&line[..i], line[i + 1..].trim_start()),
            None => (line, ""),
        };

        match verb.to_ascii_uppercase().as_str() {
            "LHLO" => {
                let client_domain = Domain::parse(rest).map_err(|_domain_err| bad())?;
                Ok(Self::Lhlo { client_domain })
            }
            "MAIL" => {
                // RFC 5321 §4.1.1.2: MAIL FROM:<reverse-path> [SP params]
                let rest = rest.strip_prefix_ci("FROM:").ok_or_else(bad)?;
                let (path_str, param_str) = split_path(rest);
                let from = parse_reverse_path(path_str).ok_or_else(bad)?;
                let parameters = parse_mail_params(param_str);
                Ok(Self::Mail { from, parameters })
            }
            "RCPT" => {
                // RFC 5321 §4.1.1.3: RCPT TO:<forward-path> [SP params]
                let rest = rest.strip_prefix_ci("TO:").ok_or_else(bad)?;
                let (path_str, param_str) = split_path(rest);
                let addr_str = path_str.trim_matches(|c| c == '<' || c == '>');
                let to = EmailAddress::parse(addr_str).map_err(|_addr_err| bad())?;
                let parameters = parse_rcpt_params(param_str);
                Ok(Self::Rcpt { to, parameters })
            }
            "DATA" => Ok(Self::Data),
            "RSET" => Ok(Self::Rset),
            "NOOP" => Ok(Self::Noop),
            "VRFY" => Ok(Self::Vrfy {
                query: rest.to_owned(),
            }),
            "QUIT" => Ok(Self::Quit),
            // RFC 2033 §4.1: HELO and EHLO are not valid in LMTP; all other verbs are unknown.
            _ => Err(bad()),
        }
    }
}

impl std::fmt::Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lhlo { client_domain } => write!(f, "LHLO {client_domain}"),
            Self::Mail { from, .. } => write!(f, "MAIL FROM:{from}"),
            Self::Rcpt { to, .. } => write!(f, "RCPT TO:<{to}>"),
            Self::Data => f.write_str("DATA"),
            Self::Rset => f.write_str("RSET"),
            Self::Noop => f.write_str("NOOP"),
            Self::Vrfy { query } => write!(f, "VRFY {query}"),
            Self::Quit => f.write_str("QUIT"),
        }
    }
}

/// An ESMTP parameter for the `MAIL FROM` command.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailParam {
    /// `SIZE=<n>` – estimated message size in octets (RFC 1870).
    Size(u64),
    /// `BODY=7BIT` – 7-bit clean body (default).
    Body7Bit,
    /// `BODY=8BITMIME` – 8-bit body; server must advertise `8BITMIME`
    /// (RFC 6152).
    Body8BitMime,
    /// An unrecognised parameter preserved verbatim.
    Unknown(String),
}

/// An ESMTP parameter for the `RCPT TO` command.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RcptParam {
    /// An unrecognised parameter preserved verbatim.
    Unknown(String),
}

// ── Private helpers ───────────────────────────────────────────────────────────

trait StripPrefixCi {
    fn strip_prefix_ci(&self, prefix: &str) -> Option<&str>;
}

impl StripPrefixCi for str {
    fn strip_prefix_ci(&self, prefix: &str) -> Option<&str> {
        (self.len() >= prefix.len() && self[..prefix.len()].eq_ignore_ascii_case(prefix))
            .then(|| &self[prefix.len()..])
    }
}

/// Split a `<path>` from any trailing SP+params, returning (path, params).
fn split_path(s: &str) -> (&str, &str) {
    if let Some(rest) = s.strip_prefix('<') {
        // Angle-bracket delimited: find the closing '>'.
        if let Some(close) = rest.find('>') {
            let path = &s[..close + 2]; // include < and >
            let params = rest[close + 1..].trim_start();
            return (path, params);
        }
    }
    // No angle brackets: path is everything up to first space.
    match s.find(|c: char| c.is_ascii_whitespace()) {
        Some(i) => (&s[..i], s[i + 1..].trim_start()),
        None => (s, ""),
    }
}

/// Parse a reverse-path string (`<>`, `<addr>`, or bare `addr`).
fn parse_reverse_path(s: &str) -> Option<OwnedReversePath> {
    let inner = s.trim();
    if inner == "<>" {
        return Some(OwnedReversePath::Null);
    }
    let addr_str = inner.trim_matches(|c| c == '<' || c == '>');
    EmailAddress::parse(addr_str)
        .ok()
        .map(OwnedReversePath::Address)
}

/// Parse ESMTP parameters from the remainder after the path (RFC 5321 §4.1.2).
fn parse_mail_params(s: &str) -> Vec<MailParam> {
    s.split_ascii_whitespace()
        .filter(|p| !p.is_empty())
        .map(|p| {
            if let Some(n) = p.strip_prefix_ci("SIZE=") {
                n.parse::<u64>()
                    .map_or_else(|_| MailParam::Unknown(p.to_owned()), MailParam::Size)
            } else if p.eq_ignore_ascii_case("BODY=7BIT") {
                MailParam::Body7Bit
            } else if p.eq_ignore_ascii_case("BODY=8BITMIME") {
                MailParam::Body8BitMime
            } else {
                MailParam::Unknown(p.to_owned())
            }
        })
        .collect()
}

fn parse_rcpt_params(s: &str) -> Vec<RcptParam> {
    s.split_ascii_whitespace()
        .filter(|p| !p.is_empty())
        .map(|p| RcptParam::Unknown(p.to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use email_primitives::address::OwnedReversePath;

    use super::{Command, MailParam};

    /// RFC 2033 §4.1: LHLO identifies the client.
    #[test]
    fn parse_lhlo() {
        let cmd = Command::parse("LHLO example.com").expect("valid LHLO");
        assert!(matches!(cmd, Command::Lhlo { .. }));
    }

    /// Case-insensitivity: verb may be lowercase (RFC 5321 §2.4).
    #[test]
    fn parse_lhlo_lowercase() {
        let cmd = Command::parse("lhlo example.com").expect("lowercase lhlo");
        assert!(matches!(cmd, Command::Lhlo { .. }));
    }

    /// RFC 5321 §4.1.1.2: MAIL FROM with null reverse-path.
    #[test]
    fn parse_mail_from_null() {
        let cmd = Command::parse("MAIL FROM:<>").expect("null path");
        assert!(matches!(
            cmd,
            Command::Mail {
                from: OwnedReversePath::Null,
                ..
            }
        ));
    }

    /// RFC 5321 §4.1.1.2: MAIL FROM with an address.
    #[test]
    fn parse_mail_from_addr() {
        let cmd = Command::parse("MAIL FROM:<user@example.com>").expect("addr path");
        assert!(matches!(
            cmd,
            Command::Mail {
                from: OwnedReversePath::Address(_),
                ..
            }
        ));
    }

    /// RFC 1870: SIZE parameter is parsed and converted to u64.
    #[test]
    fn parse_mail_from_size_param() {
        let cmd = Command::parse("MAIL FROM:<user@example.com> SIZE=12345").expect("size param");
        let Command::Mail { parameters, .. } = cmd else {
            unreachable!("MAIL FROM:<> always produces the Mail variant");
        };
        assert!(parameters.contains(&MailParam::Size(12345)));
    }

    /// RFC 5321 §4.1.1.3: RCPT TO with a forward-path.
    #[test]
    fn parse_rcpt_to() {
        let cmd = Command::parse("RCPT TO:<user@example.com>").expect("rcpt to");
        assert!(matches!(cmd, Command::Rcpt { .. }));
    }

    /// RFC 5321 §4.1.1.4: DATA requires no arguments.
    #[test]
    fn parse_data() {
        assert!(matches!(
            Command::parse("DATA").expect("data"),
            Command::Data
        ));
    }

    /// RFC 5321 §4.1.1.5: RSET requires no arguments.
    #[test]
    fn parse_rset() {
        assert!(matches!(
            Command::parse("RSET").expect("rset"),
            Command::Rset
        ));
    }

    /// RFC 5321 §4.1.1.10: QUIT requires no arguments.
    #[test]
    fn parse_quit() {
        assert!(matches!(
            Command::parse("QUIT").expect("quit"),
            Command::Quit
        ));
    }

    /// RFC 2033 §4.1: HELO is not valid in LMTP.
    #[test]
    fn parse_helo_rejected() {
        Command::parse("HELO example.com").expect_err("HELO must be rejected");
    }

    /// RFC 2033 §4.1: EHLO is not valid in LMTP.
    #[test]
    fn parse_ehlo_rejected() {
        Command::parse("EHLO example.com").expect_err("EHLO must be rejected");
    }

    /// Unknown verbs are rejected.
    #[test]
    fn parse_unknown_rejected() {
        Command::parse("FOOB example.com").expect_err("unknown verb rejected");
    }
}
