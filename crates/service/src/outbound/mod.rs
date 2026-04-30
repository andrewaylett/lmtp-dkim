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

mod downstream;
mod handler;

use crate::config::Config;

/// Run the outbound LMTP server.
#[expect(
    clippy::unused_async,
    reason = "stub: will await server.serve_* once implemented"
)]
pub(crate) async fn run(config: Config) -> anyhow::Result<()> {
    let _ = config;
    todo!(
        "1. load DKIM private keys for each config.dkim entry; \
         2. build OutboundHandler with domain-to-signer map; \
         3. configure lmtp::ServerConfig; \
         4. bind listener per config.listen; \
         5. Server::new(server_config, handler).serve_*(listener).await"
    )
}
