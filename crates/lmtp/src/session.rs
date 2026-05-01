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
//! [`MessageHandler::handle`], which returns one [`Reply`] per
//! recipient. The session then sends those replies in order.

use crate::{Result, command::Command, response::Reply};
use email_primitives::address::OwnedReversePath;
use email_primitives::{EmailAddress, Message};

use crate::Error;
use crate::response::ReplyCode;

/// The current state of an LMTP session.
#[derive(Debug)]
pub(crate) enum SessionState {
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
        sender: OwnedReversePath,
        /// Parameters from the `MAIL FROM` command.
        mail_params: Vec<crate::command::MailParam>,
    },

    /// At least one `RCPT TO` accepted. Ready for more `RCPT TO` or `DATA`.
    HasRecipients {
        /// The domain from `LHLO`.
        client_domain: email_primitives::Domain,
        /// The envelope sender.
        sender: OwnedReversePath,
        /// ESMTP parameters from `MAIL FROM`.
        mail_params: Vec<crate::command::MailParam>,
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
        sender: OwnedReversePath,
        /// ESMTP parameters from `MAIL FROM`.
        mail_params: Vec<crate::command::MailParam>,
        /// The recipients awaiting per-message responses.
        recipients: Vec<EmailAddress>,
    },

    /// `QUIT` received; `221` sent; connection should be closed.
    Done,

    /// Invalid state
    Invalid,
}

/// Envelope information for a received message.
#[non_exhaustive]
#[derive(Debug)]
pub struct Envelope {
    /// The `LHLO` domain, identifying the connecting client.
    pub client_domain: email_primitives::Domain,
    /// The `MAIL FROM` reverse-path.
    pub sender: OwnedReversePath,
    /// The accepted `RCPT TO` addresses, in order.
    pub recipients: Vec<EmailAddress>,
    /// ESMTP parameters from the `MAIL FROM` command.
    pub mail_params: Vec<crate::command::MailParam>,
}

/// Outcome of processing a single recipient's delivery.
#[non_exhaustive]
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
    ) -> impl Future<Output = Result<Vec<RecipientResult>>> + Send;
}

/// An LMTP session driving the protocol state machine over a framed transport.
///
/// The generic parameter `H` is the [`MessageHandler`] that processes received
/// messages. The session is created per TCP/Unix connection.
#[non_exhaustive]
#[derive(Debug)]
pub struct Session<H: MessageHandler> {
    /// The server's hostname, used in greeting and `QUIT` responses.
    pub hostname: String,
    state: SessionState,
    handler: H,
}

impl<H: MessageHandler> Session<H> {
    /// Construct a new session in the [`SessionState::Connected`] state.
    pub fn new<S: Into<String>>(hostname: S, handler: H) -> Self {
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
    /// Returns [`Error::OutOfSequence`] if the command is not valid in
    /// the current session state.
    ///
    /// # State transitions
    ///
    /// See the module-level state diagram.
    #[expect(
        clippy::unused_async,
        reason = "kept async for forward-compat; server calls it with .await"
    )]
    pub async fn handle_command(&mut self, command: Command) -> Result<Reply> {
        match command {
            // NOOP is valid in any state and never changes it (RFC 5321 §4.1.1.9).
            Command::Noop => Ok(Reply::ok()),
            // VRFY is valid in any state and never changes it (RFC 5321 §4.1.1.6).
            Command::Vrfy { .. } => Ok(Reply::new(ReplyCode::CANNOT_VRFY, "Cannot VRFY user")),
            // QUIT is valid in any state (RFC 5321 §4.1.1.10).
            Command::Quit => {
                self.state = SessionState::Done;
                Ok(Reply::closing(&self.hostname))
            }
            // RSET resets to Greeted from any post-LHLO state (RFC 5321 §4.1.1.5).
            Command::Rset => {
                let state = std::mem::replace(&mut self.state, SessionState::Invalid);
                match state {
                    SessionState::Greeted { client_domain }
                    | SessionState::HasSender { client_domain, .. }
                    | SessionState::HasRecipients { client_domain, .. } => {
                        self.state = SessionState::Greeted { client_domain };
                        Ok(Reply::ok())
                    }
                    other => {
                        self.state = other;
                        Err(Error::OutOfSequence(
                            "RSET not valid in current state".into(),
                        ))
                    }
                }
            }
            command => self.dispatch_command(command),
        }
    }

    /// Dispatch a state-specific command (LHLO, MAIL, RCPT, DATA) through the
    /// session state machine.
    fn dispatch_command(&mut self, command: Command) -> Result<Reply> {
        let state = std::mem::replace(&mut self.state, SessionState::Invalid);
        let (state, response) = match (state, command) {
            (SessionState::Connected, Command::Lhlo { client_domain }) => (
                SessionState::Greeted { client_domain },
                Ok(Reply::multi(
                    ReplyCode::OK,
                    vec![
                        format!("{} Hello", self.hostname),
                        "8BITMIME".to_owned(),
                        "ENHANCEDSTATUSCODES".to_owned(),
                    ],
                )),
            ),
            (state @ SessionState::Connected, _) => (
                state,
                Err(Error::OutOfSequence(
                    "expected LHLO before any other command".into(),
                )),
            ),
            (SessionState::Greeted { client_domain }, Command::Mail { from, parameters }) => (
                SessionState::HasSender {
                    client_domain,
                    sender: from,
                    mail_params: parameters,
                },
                Ok(Reply::ok()),
            ),
            (state @ SessionState::Greeted { .. }, _) => (
                state,
                Err(Error::OutOfSequence("expected MAIL FROM".into())),
            ),
            (
                SessionState::HasSender {
                    client_domain,
                    sender,
                    mail_params,
                },
                Command::Rcpt { to, .. },
            ) => (
                SessionState::HasRecipients {
                    client_domain,
                    sender,
                    mail_params,
                    recipients: vec![to],
                },
                Ok(Reply::ok()),
            ),
            (state @ SessionState::HasSender { .. }, _) => {
                (state, Err(Error::OutOfSequence("expected RCPT TO".into())))
            }
            (
                SessionState::HasRecipients {
                    client_domain,
                    sender,
                    mail_params,
                    mut recipients,
                },
                Command::Rcpt { to, .. },
            ) => {
                recipients.push(to);
                (
                    SessionState::HasRecipients {
                        client_domain,
                        sender,
                        mail_params,
                        recipients,
                    },
                    Ok(Reply::ok()),
                )
            }
            (
                SessionState::HasRecipients {
                    client_domain,
                    sender,
                    mail_params,
                    recipients,
                },
                Command::Data,
            ) => (
                SessionState::Transferring {
                    client_domain,
                    sender,
                    mail_params,
                    recipients,
                },
                Ok(Reply::start_data()),
            ),
            (state @ SessionState::HasRecipients { .. }, _) => (
                state,
                Err(Error::OutOfSequence("expected RCPT TO or DATA".into())),
            ),
            (state, _) => (
                state,
                Err(Error::OutOfSequence(
                    "command received in unexpected state".into(),
                )),
            ),
        };
        self.state = state;
        response
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
    pub async fn receive_data(&mut self, raw: bytes::Bytes) -> Result<Vec<Reply>> {
        let SessionState::Transferring {
            client_domain,
            sender,
            mail_params,
            recipients,
        } = std::mem::replace(&mut self.state, SessionState::Invalid)
        else {
            return Err(Error::OutOfSequence(
                "receive_data called outside Transferring state".into(),
            ));
        };

        let greeted_domain = client_domain.clone();
        let message = Message::parse(&raw)?;
        let envelope = Envelope {
            client_domain,
            sender,
            recipients,
            mail_params,
        };
        let results = self.handler.handle(envelope, message).await?;
        self.state = SessionState::Greeted {
            client_domain: greeted_domain,
        };
        Ok(results.into_iter().map(|r| r.reply).collect())
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{Envelope, MessageHandler, RecipientResult, Session};
    use crate::{Command, Error, Reply, ReplyCode, Result};
    use email_primitives::Message;

    struct NoopHandler;

    impl MessageHandler for NoopHandler {
        async fn handle(
            &self,
            envelope: Envelope,
            _message: Message,
        ) -> Result<Vec<RecipientResult>> {
            Ok(envelope
                .recipients
                .into_iter()
                .map(|recipient| RecipientResult {
                    recipient,
                    reply: Reply::ok(),
                })
                .collect())
        }
    }

    fn session() -> Session<NoopHandler> {
        Session::new("mx.example.com", NoopHandler)
    }

    /// Greeting uses `SERVICE_READY` (220) and includes the hostname.
    #[test]
    fn greeting_reply() {
        let s = session();
        let r = s.greeting();
        assert_eq!(r.code, ReplyCode::SERVICE_READY);
        assert!(r.lines[0].contains("mx.example.com"));
    }

    /// LHLO in Connected state transitions to Greeted and returns 250.
    #[tokio::test]
    async fn lhlo_transitions_to_greeted() {
        let mut s = session();
        let cmd = Command::parse("LHLO client.example.com").expect("valid LHLO");
        let reply = s.handle_command(cmd).await.expect("LHLO accepted");
        assert!(reply.code.is_positive());
    }

    /// MAIL FROM in Connected state (before LHLO) returns `OutOfSequence`.
    #[tokio::test]
    async fn mail_before_lhlo_rejected() {
        let mut s = session();
        let cmd = Command::parse("MAIL FROM:<>").expect("valid MAIL");
        let err = s.handle_command(cmd).await.expect_err("should be rejected");
        assert!(matches!(err, Error::OutOfSequence(_)));
    }

    /// DATA before any RCPT TO (in `HasSender`) returns `OutOfSequence`.
    #[tokio::test]
    async fn data_before_rcpt_rejected() {
        let mut s = session();
        s.handle_command(Command::parse("LHLO client.example.com").expect("lhlo"))
            .await
            .expect("lhlo ok");
        s.handle_command(Command::parse("MAIL FROM:<>").expect("mail"))
            .await
            .expect("mail ok");
        let err = s
            .handle_command(Command::parse("DATA").expect("data"))
            .await
            .expect_err("DATA before RCPT should fail");
        assert!(matches!(err, Error::OutOfSequence(_)));
    }

    /// RSET from `HasRecipients` returns to Greeted (reply is 250).
    #[tokio::test]
    async fn rset_resets_to_greeted() {
        let mut s = session();
        s.handle_command(Command::parse("LHLO client.example.com").expect("lhlo"))
            .await
            .expect("lhlo ok");
        s.handle_command(Command::parse("MAIL FROM:<>").expect("mail"))
            .await
            .expect("mail ok");
        s.handle_command(Command::parse("RCPT TO:<user@example.com>").expect("rcpt"))
            .await
            .expect("rcpt ok");
        let reply = s
            .handle_command(Command::parse("RSET").expect("rset"))
            .await
            .expect("rset ok");
        assert_eq!(reply.code, ReplyCode::OK);
    }

    /// Full transaction: LHLO → MAIL → RCPT → DATA → `receive_data`.
    #[tokio::test]
    async fn full_transaction() {
        let mut s = session();
        s.handle_command(Command::parse("LHLO client.example.com").expect("lhlo"))
            .await
            .expect("lhlo");
        s.handle_command(Command::parse("MAIL FROM:<sender@example.com>").expect("mail"))
            .await
            .expect("mail");
        s.handle_command(Command::parse("RCPT TO:<rcpt@example.com>").expect("rcpt"))
            .await
            .expect("rcpt");
        let data_reply = s
            .handle_command(Command::parse("DATA").expect("data"))
            .await
            .expect("data");
        assert_eq!(data_reply.code, ReplyCode::START_MAIL_INPUT);

        // Minimal valid RFC 5322 message.
        let raw = Bytes::from("Subject: test\r\n\r\nbody\r\n");
        let replies = s.receive_data(raw).await.expect("receive_data");
        assert_eq!(replies.len(), 1);
        assert!(replies[0].code.is_positive());
    }
}
