//! Async LMTP server implementation.
//!
//! # LMTP vs SMTP
//!
//! LMTP (Local Mail Transfer Protocol, [RFC 2033]) is designed for delivery
//! to a final message store, not for relaying across the Internet. Key
//! differences from SMTP ([RFC 5321]):
//!
//! | Feature | SMTP | LMTP |
//! |---------|------|------|
//! | Greeting command | `EHLO`/`HELO` | `LHLO` |
//! | `HELO` supported | yes | **no** |
//! | Per-transaction response | single after DATA | **one per recipient** |
//! | Suitable for relaying | yes | **no** (local delivery only) |
//! | Transport | TCP port 25 | usually Unix socket or TCP loopback |
//!
//! The per-recipient DATA response is the most important distinction. After
//! the message data is transferred, the server sends one `250`/`4xx`/`5xx`
//! response for each accepted `RCPT TO` address, in the order they were
//! accepted (RFC 2033 section 4.2).
//!
//! # Session state machine
//!
//! ```text
//!  ┌──────────┐  LHLO  ┌─────────┐  MAIL FROM  ┌──────────┐
//!  │ Connected │───────▶│ Greeted │────────────▶│ HasSender│
//!  └──────────┘        └─────────┘             └──────────┘
//!                         ▲  ▲                      │
//!                  RSET   │  │ per-rcpt responses   │ RCPT TO
//!                         │  │ sent; loop back       ▼
//!                    ┌────┴──┴───┐  DATA   ┌──────────────┐
//!                    │HasRecipient│◀───────│  Transferring │
//!                    └───────────┘         └──────────────┘
//!                          │
//!                          │ RCPT TO (accumulate)
//!                          ▼
//!                    ┌───────────┐
//!                    │HasRecipient│ (same state, more recipients)
//!                    └───────────┘
//! ```
//!
//! Any state accepts `NOOP`, `VRFY`, and `QUIT`. `RSET` returns to the
//! `Greeted` state.
//!
//! # Extensions
//!
//! LMTP servers advertise extensions in response to `LHLO` using the same
//! mechanism as ESMTP. Relevant extensions for this service:
//!
//! - `8BITMIME` (RFC 6152) – accept 8-bit message bodies.
//! - `CHUNKING` (RFC 3030) – `BDAT` command as alternative to `DATA`.
//!   Not planned for initial implementation.
//! - `ENHANCEDSTATUSCODES` (RFC 2034) – structured status codes like `2.1.0`.
//! - `SIZE` (RFC 1870) – advertise maximum accepted message size.
//!
//! [RFC 2033]: https://www.rfc-editor.org/rfc/rfc2033
//! [RFC 5321]: https://www.rfc-editor.org/rfc/rfc5321
//!
//! # Module layout
//!
//! - [`codec`]   – tokio [`LinesCodec`][tokio_util::codec::LinesCodec]-based
//!   framing for LMTP lines and the DATA body.
//! - [`command`] – parsed representations of client commands.
//! - [`response`] – server response codes and reply text.
//! - [`session`] – session state machine.
//! - [`server`]  – TCP/Unix-socket listener that spawns sessions.

#![warn(missing_docs)]

pub mod codec;
pub mod command;
pub mod response;
pub mod server;
pub mod session;

pub use command::Command;
pub use response::{Reply, ReplyCode};
pub use server::{Server, ServerConfig};
pub use session::Session;

use thiserror::Error;

/// Errors that can arise in LMTP processing.
#[derive(Debug, Error)]
pub enum Error {
    /// An I/O error on the underlying transport.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A command received from the client could not be parsed.
    #[error("unrecognised or malformed command: {0:?}")]
    BadCommand(String),

    /// A command arrived that is not valid in the current session state.
    ///
    /// For example, `DATA` before any `RCPT TO` has been accepted.
    #[error("command out of sequence: {0}")]
    OutOfSequence(String),

    /// The underlying email-primitives library reported an error.
    #[error("email primitive error: {0}")]
    Primitive(#[from] email_primitives::Error),
}

/// Convenience `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;
