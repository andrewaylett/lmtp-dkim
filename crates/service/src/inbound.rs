//! Inbound mail processing: validate and ARC-seal.
//!
//! # Pipeline
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │  Inbound LMTP session receives envelope + message            │
//! │                                                               │
//! │  1. Verify DKIM signatures (all DKIM-Signature headers)      │
//! │     → VerificationResult per signature                        │
//! │                                                               │
//! │  2. Validate existing ARC chain (if any ARC headers present) │
//! │     → ArcChainResult (none / pass / fail)                     │
//! │                                                               │
//! │  3. Evaluate SPF (via hickory-resolver DNS lookups)          │
//! │     → SpfResult  [future: may delegate to external library]  │
//! │                                                               │
//! │  4. Build Authentication-Results reflecting steps 1-3        │
//! │                                                               │
//! │  5. ARC-seal: add AAR + AMS + AS (if i ≤ 50)                │
//! │                                                               │
//! │  6. Forward modified message downstream via LMTP             │
//! │     → per-recipient response propagated back to client       │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # SPF note
//!
//! SPF (RFC 7208) requires access to the SMTP envelope `MAIL FROM` and the
//! connecting IP address, which are available in the LMTP session envelope.
//! SPF evaluation is not implemented in this crate; a third-party library or
//! external service should be used. The result is recorded in the AAR.
//!
//! # DMARC note
//!
//! DMARC (RFC 7489) alignment is computed from the SPF and DKIM results. If
//! DMARC fails, the message is still processed and the failure is recorded in
//! the Authentication-Results header. Rejection policy enforcement is left to
//! the downstream MTA.
//!
//! # Error handling
//!
//! If signing fails (e.g. key load error, DNS timeout), we still deliver the
//! message but without the ARC set. A `tempfail` should be returned to the
//! client if adding ARC is required; otherwise the message is forwarded as-is
//! with a warning log.

use std::sync::Arc as StdArc;

use email_primitives::Message;
use lmtp::session::{Envelope, MessageHandler, RecipientResult};
#[expect(
    unused_imports,
    reason = "stub: tracing macros used when run() is implemented"
)]
use tracing::{error, info, warn};

use crate::config::Config;

/// Run the inbound LMTP server.
///
/// Binds to the configured listen socket, creates the signing infrastructure,
/// and serves connections.
#[expect(
    clippy::unused_async,
    reason = "stub: will await server.serve_* once implemented"
)]
pub async fn run(config: Config) -> anyhow::Result<()> {
    let _ = config;
    todo!(
        "1. load ARC private key from config.arc.key_file; \
         2. create DkimResolver and ArcResolver; \
         3. build InboundHandler; \
         4. configure lmtp::ServerConfig; \
         5. bind listener per config.listen; \
         6. Server::new(server_config, handler).serve_*(listener).await"
    )
}

/// LMTP [`MessageHandler`] for the inbound pipeline.
#[derive(Clone)]
#[expect(dead_code, reason = "stub: constructed in run() once implemented")]
pub struct InboundHandler {
    inner: StdArc<InboundHandlerInner>,
}

#[expect(
    dead_code,
    reason = "stub: fields used by MessageHandler::handle once implemented"
)]
struct InboundHandlerInner {
    arc_signer: arc::ArcSigner,
    dkim_verifier: dkim::Verifier,
    arc_validator: arc::ChainValidator,
    downstream: DownstreamClient,
    authserv_id: String,
}

impl MessageHandler for InboundHandler {
    async fn handle(
        &self,
        envelope: Envelope,
        message: Message,
    ) -> lmtp::Result<Vec<RecipientResult>> {
        let _ = (envelope, message);
        todo!(
            "1. dkim_verifier.verify(&message); \
             2. arc_validator.validate(&message); \
             3. evaluate SPF (envelope.sender, client IP from LHLO domain); \
             4. build SealRequest with auth results; \
             5. arc_signer.seal(&message, chain_result, seal_request); \
             6. downstream.deliver(envelope, sealed_message); \
             7. map downstream per-recipient replies to RecipientResult"
        )
    }
}

/// Client for forwarding messages to the downstream LMTP server.
///
/// Initiates an LMTP session (sends LHLO, MAIL FROM, RCPT TO ×N, DATA)
/// and collects per-recipient responses.
#[expect(
    dead_code,
    reason = "stub: constructed in InboundHandlerInner once implemented"
)]
struct DownstreamClient {
    // connection pool or address config
}

impl DownstreamClient {
    /// Forward a message to the downstream LMTP server.
    ///
    /// Returns one [`RecipientResult`] per entry in `envelope.recipients`,
    /// suitable for passing back to the upstream client.
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
             send LHLO; MAIL FROM; RCPT TO * recipients; DATA; \
             collect per-recipient 250/4xx/5xx replies; close or cache connection"
        )
    }
}
