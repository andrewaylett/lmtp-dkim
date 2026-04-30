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

mod downstream;
mod handler;

use crate::config::Config;

/// Run the inbound LMTP server.
///
/// Binds to the configured listen socket, creates the signing infrastructure,
/// and serves connections.
#[expect(
    clippy::unused_async,
    reason = "stub: will await server.serve_* once implemented"
)]
pub(crate) async fn run(config: Config) -> anyhow::Result<()> {
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
