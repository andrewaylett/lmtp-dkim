//! Outbound mail processing: DKIM-sign user-submitted mail.
//!
//! # Pipeline
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │  Outbound LMTP session receives envelope + message           │
//! │                                                               │
//! │  1. Determine the signing domain                             │
//! │     - Extract `From:` header domain                          │
//! │     - Look up matching DkimSigningConfig                     │
//! │     - If no matching config → deliver unsigned (with warning)│
//! │                                                               │
//! │  2. DKIM-sign the message                                    │
//! │     - Canonicalize body; compute bh=                         │
//! │     - Sign selected headers; prepend DKIM-Signature          │
//! │                                                               │
//! │  3. Forward signed message downstream via LMTP/SMTP          │
//! │     → per-recipient response propagated back to client       │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Domain selection
//!
//! The signing domain is derived from the `From:` header. If the message has
//! multiple `From:` values (unusual), the last (innermost) one is used. If
//! no matching [`crate::config::DkimSigningConfig`] exists for the domain,
//! the message is forwarded unsigned and a warning is emitted.
//!
//! # Key management
//!
//! Private keys are loaded at startup from PEM files and kept in memory for
//! the lifetime of the service. Key rotation requires a service restart or
//! a SIGHUP-triggered reload (not implemented in the initial version).
//!
//! # Multi-domain support
//!
//! The `[[dkim]]` configuration section is a list, so multiple domains can
//! be served by a single instance. Each incoming message is signed with the
//! key corresponding to its `From:` domain.

use std::collections::HashMap;
use std::sync::Arc as StdArc;

use email_primitives::Message;
use lmtp::session::{Envelope, MessageHandler, RecipientResult};
#[expect(
    unused_imports,
    reason = "stub: tracing macros used when run() is implemented"
)]
use tracing::{info, warn};

use crate::config::Config;

/// Run the outbound LMTP server.
#[expect(
    clippy::unused_async,
    reason = "stub: will await server.serve_* once implemented"
)]
pub async fn run(config: Config) -> anyhow::Result<()> {
    let _ = config;
    todo!(
        "1. load DKIM private keys for each config.dkim entry; \
         2. build OutboundHandler with domain-to-signer map; \
         3. configure lmtp::ServerConfig; \
         4. bind listener per config.listen; \
         5. Server::new(server_config, handler).serve_*(listener).await"
    )
}

/// LMTP [`MessageHandler`] for the outbound pipeline.
#[derive(Clone)]
#[expect(dead_code, reason = "stub: constructed in run() once implemented")]
pub struct OutboundHandler {
    inner: StdArc<OutboundHandlerInner>,
}

#[expect(
    dead_code,
    reason = "stub: fields used by MessageHandler::handle once implemented"
)]
struct OutboundHandlerInner {
    /// Map from lowercase domain string to configured signer.
    ///
    /// Keyed by the `d=` domain as configured in `[[dkim]]`.
    signers: HashMap<String, dkim::Signer>,
    downstream: DownstreamClient,
}

impl MessageHandler for OutboundHandler {
    async fn handle(
        &self,
        envelope: Envelope,
        message: Message,
    ) -> lmtp::Result<Vec<RecipientResult>> {
        let _ = (envelope, message);
        todo!(
            "1. extract From: header domain; \
             2. look up self.inner.signers.get(domain); \
             3. if found: signer.sign(&message); \
             4. if not found: warn and use unsigned message; \
             5. downstream.deliver(envelope, signed_or_original_message); \
             6. return per-recipient RecipientResult"
        )
    }
}

/// Client for forwarding signed messages downstream.
///
/// Identical in structure to the inbound [`crate::inbound::DownstreamClient`];
/// consider extracting to a shared module once both modes are implemented.
#[expect(
    dead_code,
    reason = "stub: constructed in OutboundHandlerInner once implemented"
)]
struct DownstreamClient {
    // connection pool or address config
}

impl DownstreamClient {
    #[expect(
        dead_code,
        reason = "stub: called by MessageHandler::handle once implemented"
    )]
    #[expect(
        clippy::unused_async,
        reason = "stub: will await LMTP connection once implemented"
    )]
    async fn deliver(
        &self,
        _envelope: &Envelope,
        _message: &Message,
    ) -> lmtp::Result<Vec<RecipientResult>> {
        todo!(
            "open TCP/Unix connection to downstream; \
             LHLO, MAIL FROM, RCPT TO, DATA; \
             collect per-recipient replies"
        )
    }
}
