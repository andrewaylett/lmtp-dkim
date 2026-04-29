//! LMTP server response types.
//!
//! LMTP uses the same reply code system as SMTP (RFC 5321 section 4.2).
//! Reply codes are three-digit numbers where:
//!
//! - First digit: success class
//!   - `2xx` – Positive completion (command succeeded)
//!   - `3xx` – Positive intermediate (more input needed, e.g. `354`)
//!   - `4xx` – Transient negative (temporary failure, client may retry)
//!   - `5xx` – Permanent negative (persistent failure, do not retry)
//!
//! - Second digit: category
//!   - `x0x` – Syntax
//!   - `x1x` – Information
//!   - `x2x` – Connections
//!   - `x5x` – Mail system
//!
//! # Multi-line replies
//!
//! A reply may span multiple lines. Each intermediate line uses `<code>-<text>`
//! and the final line uses `<code> <text>` (RFC 5321 section 4.2.1).
//!
//! # Enhanced status codes
//!
//! When the `ENHANCEDSTATUSCODES` extension is active, each reply line begins
//! with a structured status code of the form `<class>.<subject>.<detail>`
//! (RFC 2034). For example: `250 2.1.0 Sender OK`.
//!
//! # Per-recipient responses (LMTP-specific)
//!
//! After the `DATA` body is transferred, the server sends exactly one reply
//! per accepted `RCPT TO`, in the same order (RFC 2033 section 4.2). This
//! allows the client to handle per-recipient delivery failures without
//! resubmitting the entire message.

/// A three-digit SMTP/LMTP reply code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReplyCode(u16);

impl ReplyCode {
    // ── Frequently used codes ────────────────────────────────────────────────

    /// `211 System status` (RFC 5321).
    pub const SYSTEM_STATUS: ReplyCode = ReplyCode(211);
    /// `214 Help message` (RFC 5321).
    pub const HELP: ReplyCode = ReplyCode(214);
    /// `220 <domain> Service ready` – sent immediately after TCP connection.
    pub const SERVICE_READY: ReplyCode = ReplyCode(220);
    /// `221 <domain> Service closing` – sent in response to `QUIT`.
    pub const SERVICE_CLOSING: ReplyCode = ReplyCode(221);
    /// `250 Requested mail action okay, completed`.
    pub const OK: ReplyCode = ReplyCode(250);
    /// `252 Cannot VRFY user, but will accept message and attempt delivery`.
    pub const CANNOT_VRFY: ReplyCode = ReplyCode(252);
    /// `354 Start mail input; end with <CRLF>.<CRLF>` – response to `DATA`.
    pub const START_MAIL_INPUT: ReplyCode = ReplyCode(354);
    /// `421 <domain> Service not available, closing channel`.
    pub const SERVICE_UNAVAILABLE: ReplyCode = ReplyCode(421);
    /// `450 Requested mail action not taken: mailbox unavailable` (transient).
    pub const MAILBOX_UNAVAILABLE_TRANSIENT: ReplyCode = ReplyCode(450);
    /// `451 Requested action aborted: local error in processing`.
    pub const LOCAL_ERROR: ReplyCode = ReplyCode(451);
    /// `452 Requested action not taken: insufficient system storage`.
    pub const INSUFFICIENT_STORAGE_TRANSIENT: ReplyCode = ReplyCode(452);
    /// `500 Syntax error, command unrecognised`.
    pub const SYNTAX_ERROR: ReplyCode = ReplyCode(500);
    /// `501 Syntax error in parameters or arguments`.
    pub const PARAM_SYNTAX_ERROR: ReplyCode = ReplyCode(501);
    /// `502 Command not implemented`.
    pub const NOT_IMPLEMENTED: ReplyCode = ReplyCode(502);
    /// `503 Bad sequence of commands`.
    pub const BAD_SEQUENCE: ReplyCode = ReplyCode(503);
    /// `504 Command parameter not implemented`.
    pub const PARAM_NOT_IMPLEMENTED: ReplyCode = ReplyCode(504);
    /// `550 Requested action not taken: mailbox unavailable` (permanent).
    pub const MAILBOX_UNAVAILABLE: ReplyCode = ReplyCode(550);
    /// `552 Requested mail action aborted: exceeded storage allocation`.
    pub const STORAGE_EXCEEDED: ReplyCode = ReplyCode(552);
    /// `554 Transaction failed / No SMTP service here`.
    pub const TRANSACTION_FAILED: ReplyCode = ReplyCode(554);

    /// Construct a reply code from a raw `u16`.
    ///
    /// # Panics
    ///
    /// Panics if `code` is not in `200..=599`.
    pub fn new(code: u16) -> Self {
        assert!((200..=599).contains(&code), "reply code out of range: {code}");
        ReplyCode(code)
    }

    /// The numeric value.
    pub fn as_u16(self) -> u16 {
        self.0
    }

    /// True if this is a positive-completion code (2xx).
    pub fn is_positive(&self) -> bool {
        (200..300).contains(&self.0)
    }

    /// True if this is a transient failure (4xx).
    pub fn is_transient(&self) -> bool {
        (400..500).contains(&self.0)
    }

    /// True if this is a permanent failure (5xx).
    pub fn is_permanent(&self) -> bool {
        (500..600).contains(&self.0)
    }
}

impl std::fmt::Display for ReplyCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A complete server reply, potentially spanning multiple lines.
///
/// On the wire, a multi-line reply is:
/// ```text
/// <code>-<line1>\r\n
/// <code>-<line2>\r\n
/// <code> <lastline>\r\n
/// ```
#[derive(Debug, Clone)]
pub struct Reply {
    /// The reply code.
    pub code: ReplyCode,
    /// The text lines of the reply. Must not be empty.
    pub lines: Vec<String>,
}

impl Reply {
    /// Construct a single-line reply.
    pub fn new(code: ReplyCode, text: impl Into<String>) -> Self {
        Self {
            code,
            lines: vec![text.into()],
        }
    }

    /// Construct a multi-line reply (e.g. `LHLO` extension listing).
    pub fn multi(code: ReplyCode, lines: Vec<String>) -> Self {
        assert!(!lines.is_empty(), "reply must have at least one line");
        Self { code, lines }
    }

    /// Render the reply to its wire representation including CRLF terminators.
    pub fn to_wire(&self) -> String {
        let mut out = String::new();
        for (i, line) in self.lines.iter().enumerate() {
            let sep = if i + 1 == self.lines.len() { ' ' } else { '-' };
            out.push_str(&format!("{}{}{}\r\n", self.code, sep, line));
        }
        out
    }

    // ── Common replies ───────────────────────────────────────────────────────

    /// `220 <hostname> LMTP service ready`
    pub fn greeting(hostname: &str) -> Self {
        Self::new(ReplyCode::SERVICE_READY, format!("{hostname} LMTP service ready"))
    }

    /// `221 <hostname> Bye`
    pub fn closing(hostname: &str) -> Self {
        Self::new(ReplyCode::SERVICE_CLOSING, format!("{hostname} Bye"))
    }

    /// `250 OK`
    pub fn ok() -> Self {
        Self::new(ReplyCode::OK, "OK")
    }

    /// `354 End data with <CR><LF>.<CR><LF>`
    pub fn start_data() -> Self {
        Self::new(ReplyCode::START_MAIL_INPUT, "End data with <CR><LF>.<CR><LF>")
    }

    /// `500 Syntax error, command unrecognised`
    pub fn syntax_error() -> Self {
        Self::new(ReplyCode::SYNTAX_ERROR, "Syntax error, command unrecognised")
    }

    /// `503 Bad sequence of commands`
    pub fn bad_sequence() -> Self {
        Self::new(ReplyCode::BAD_SEQUENCE, "Bad sequence of commands")
    }
}

impl std::fmt::Display for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_wire())
    }
}
