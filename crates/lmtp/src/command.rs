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

use email_primitives::{Domain, EmailAddress, NullPath};

use crate::Result;

/// A parsed LMTP client command.
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
        from: NullPath,
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
    /// Returns [`crate::Error::BadCommand`] if the line cannot be parsed as a
    /// valid LMTP command.
    pub fn parse(_line: &str) -> Result<Self> {
        todo!(
            "winnow parser: case-insensitive verb match, then parse arguments; \
             reject HELO/EHLO with 500 (RFC 2033 §4.1)"
        )
    }
}

impl std::fmt::Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Lhlo { client_domain } => write!(f, "LHLO {client_domain}"),
            Command::Mail { from, .. } => write!(f, "MAIL FROM:{from}"),
            Command::Rcpt { to, .. } => write!(f, "RCPT TO:<{to}>"),
            Command::Data => f.write_str("DATA"),
            Command::Rset => f.write_str("RSET"),
            Command::Noop => f.write_str("NOOP"),
            Command::Vrfy { query } => write!(f, "VRFY {query}"),
            Command::Quit => f.write_str("QUIT"),
        }
    }
}

/// An ESMTP parameter for the `MAIL FROM` command.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RcptParam {
    /// An unrecognised parameter preserved verbatim.
    Unknown(String),
}
