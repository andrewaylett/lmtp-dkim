//! LMTP session state machine.
//!
//! A session begins when a client connects. The server sends a `220` greeting
//! and enters the [`SessionState::Connected`] state. The lifecycle is:
//!
//! ```text
//! Connected ─LHLO──▶ Greeted ─MAIL FROM──▶ HasSender ─RCPT TO──▶ HasRecipients
//!                      ▲                                               │
//!                      │◀──────────────────── RSET ───────────────────┘
//!                      │◀─── per-recipient responses sent after DATA ──┘
//!                                                                      │DATA
//!                                                               Transferring
//! ```
//!
//! # Message handler
//!
//! The session delegates the actual processing (signing, forwarding) to a
//! [`MessageHandler`] implementation supplied by the caller. This keeps the
//! protocol state machine decoupled from the application logic.
//!
//! After the complete message has been received, the session calls
//! [`MessageHandler::handle`], which returns one [`crate::Reply`] per
//! recipient. The session then sends those replies in order.

use email_primitives::{EmailAddress, Message, NullPath};

use crate::{Result, response::Reply};

/// The current state of an LMTP session.
#[derive(Debug)]
pub enum SessionState {
    /// TCP connection established; `220` greeting sent; waiting for `LHLO`.
    Connected,

    /// `LHLO` received and accepted. Ready for `MAIL FROM`.
    Greeted {
        /// The domain the client reported in `LHLO`.
        client_domain: email_primitives::Domain,
    },

    /// `MAIL FROM` accepted. Ready for `RCPT TO`.
    HasSender {
        /// The domain from `LHLO`.
        client_domain: email_primitives::Domain,
        /// The envelope sender.
        sender: NullPath,
        /// Parameters from the `MAIL FROM` command.
        mail_params: Vec<crate::command::MailParam>,
    },

    /// At least one `RCPT TO` accepted. Ready for more `RCPT TO` or `DATA`.
    HasRecipients {
        /// The domain from `LHLO`.
        client_domain: email_primitives::Domain,
        /// The envelope sender.
        sender: NullPath,
        /// Accepted recipients, in the order they were received.
        ///
        /// LMTP requires that per-recipient DATA responses are sent in the
        /// same order as the `RCPT TO` commands (RFC 2033 section 4.2).
        recipients: Vec<EmailAddress>,
    },

    /// `DATA` command received and `354` sent. Accumulating message data.
    Transferring {
        /// The domain from `LHLO`.
        client_domain: email_primitives::Domain,
        /// The envelope sender.
        sender: NullPath,
        /// The recipients awaiting per-message responses.
        recipients: Vec<EmailAddress>,
    },

    /// `QUIT` received; `221` sent; connection should be closed.
    Done,
}

/// Envelope information for a received message.
#[derive(Debug)]
pub struct Envelope {
    /// The `LHLO` domain, identifying the connecting client.
    pub client_domain: email_primitives::Domain,
    /// The `MAIL FROM` reverse-path.
    pub sender: NullPath,
    /// The accepted `RCPT TO` addresses, in order.
    pub recipients: Vec<EmailAddress>,
}

/// Outcome of processing a single recipient's delivery.
#[derive(Debug, Clone)]
pub struct RecipientResult {
    /// The recipient address.
    pub recipient: EmailAddress,
    /// The reply to send to the client for this recipient.
    ///
    /// Must be a `2xx`, `4xx`, or `5xx` reply. The LMTP client will record
    /// permanent failures (`5xx`) and retry transient failures (`4xx`).
    pub reply: Reply,
}

/// Application-level hook called when a complete message has been received.
///
/// Implementors process the message (validate, sign, forward) and return one
/// [`RecipientResult`] per recipient. The session sends the results to the
/// client in the order returned, which must match the order of `recipients` in
/// the [`Envelope`].
///
/// # Async
///
/// This trait uses `async fn` in trait position (stabilised in Rust 1.75 via
/// RPITIT). Implementations may perform async I/O (DNS, downstream LMTP,
/// signing).
pub trait MessageHandler: Send + Sync {
    /// Process a received message and return per-recipient outcomes.
    ///
    /// The returned `Vec` must have the same length as `envelope.recipients`
    /// and in the same order.
    fn handle(
        &self,
        envelope: Envelope,
        message: Message,
    ) -> impl std::future::Future<Output = Result<Vec<RecipientResult>>> + Send;
}

/// An LMTP session driving the protocol state machine over a framed transport.
///
/// The generic parameter `H` is the [`MessageHandler`] that processes received
/// messages. The session is created per TCP/Unix connection.
pub struct Session<H: MessageHandler> {
    /// The server's hostname, used in greeting and `QUIT` responses.
    pub hostname: String,
    #[expect(dead_code, reason = "stub: used by handle_command() once implemented")]
    state: SessionState,
    #[expect(dead_code, reason = "stub: used by receive_data() once implemented")]
    handler: H,
}

impl<H: MessageHandler> Session<H> {
    /// Construct a new session in the [`SessionState::Connected`] state.
    pub fn new(hostname: impl Into<String>, handler: H) -> Self {
        Self {
            hostname: hostname.into(),
            state: SessionState::Connected,
            handler,
        }
    }

    /// Return the initial `220` greeting reply.
    ///
    /// Must be sent immediately after the TCP connection is accepted, before
    /// reading any data from the client.
    pub fn greeting(&self) -> Reply {
        Reply::greeting(&self.hostname)
    }

    /// Process a parsed command from the client and return the reply.
    ///
    /// For most commands this is a single reply. For `DATA`, the session
    /// accumulates the message body separately via [`Session::receive_data`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::OutOfSequence`] if the command is not valid in
    /// the current session state.
    ///
    /// # State transitions
    ///
    /// See the module-level state diagram.
    #[expect(
        clippy::unused_async,
        reason = "stub: will await handler once implemented"
    )]
    pub async fn handle_command(&mut self, _command: crate::command::Command) -> Result<Reply> {
        todo!(
            "match self.state and command; transition state; \
             return appropriate reply or Error::OutOfSequence"
        )
    }

    /// Receive the complete message body (after the client has been sent `354`)
    /// and invoke the [`MessageHandler`].
    ///
    /// Returns one [`Reply`] per recipient (in the order they were accepted).
    /// The caller must send all of them before reading the next command.
    ///
    /// # Errors
    ///
    /// Returns an error if message parsing fails or the handler returns an
    /// error.
    ///
    /// # Dot-unstuffing
    ///
    /// The raw bytes received from the codec already have dot-stuffing removed
    /// (a leading `.` on any line is stripped by the [`crate::codec`] layer).
    ///
    /// # State transition
    ///
    /// On success, resets to [`SessionState::Greeted`] so the client can begin
    /// a new transaction.
    #[expect(
        clippy::unused_async,
        reason = "stub: will await handler once implemented"
    )]
    pub async fn receive_data(&mut self, _raw: bytes::Bytes) -> Result<Vec<Reply>> {
        todo!(
            "parse Message from raw bytes; call self.handler.handle(envelope, message); \
             map RecipientResult to Reply vec; reset state to Greeted"
        )
    }
}
