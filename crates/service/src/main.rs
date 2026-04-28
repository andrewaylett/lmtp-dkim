//! `lmtp-dkim` – email signing and ARC-sealing service.
//!
//! # Modes of operation
//!
//! ## Inbound (Internet → internal delivery)
//!
//! ```text
//! Internet MTA  ──LMTP──▶  lmtp-dkim (inbound)  ──LMTP──▶  Mailstore / next hop
//!                               │
//!                               ├─ verify DKIM signatures
//!                               ├─ validate ARC chain
//!                               ├─ add Authentication-Results
//!                               └─ ARC-seal and forward
//! ```
//!
//! The inbound handler validates incoming mail and adds an ARC set recording
//! the authentication state, then forwards via LMTP to the configured
//! downstream.
//!
//! ## Outbound (User → Internet relay)
//!
//! ```text
//! MUA / submission  ──LMTP──▶  lmtp-dkim (outbound)  ──LMTP──▶  Internet relay
//!                                    │
//!                                    └─ DKIM-sign and forward
//! ```
//!
//! The outbound handler DKIM-signs user-submitted mail and forwards it to the
//! configured relay.
//!
//! # Configuration
//!
//! See [`config::Config`] for the full configuration schema. A TOML file is
//! provided via `--config` or the `LMTP_DKIM_CONFIG` environment variable.
//!
//! # Example invocations
//!
//! ```sh
//! # Run in inbound mode, listening on a Unix socket:
//! lmtp-dkim --config /etc/lmtp-dkim/inbound.toml
//!
//! # Run in outbound mode:
//! lmtp-dkim --config /etc/lmtp-dkim/outbound.toml
//! ```

#![warn(missing_docs)]

mod config;
mod inbound;
mod outbound;

use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Command-line arguments.
#[derive(Debug, Parser)]
#[command(name = "lmtp-dkim", about = "LMTP DKIM-signing and ARC-sealing service")]
struct Args {
    /// Path to the TOML configuration file.
    ///
    /// Falls back to the `LMTP_DKIM_CONFIG` environment variable, then to
    /// `/etc/lmtp-dkim/config.toml`.
    #[arg(short, long, env = "LMTP_DKIM_CONFIG")]
    config: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise structured logging. The `RUST_LOG` env var controls filtering.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let config = config::Config::load(args.config.as_deref())?;

    info!(mode = ?config.mode, "starting lmtp-dkim");

    match config.mode {
        config::Mode::Inbound => inbound::run(config).await?,
        config::Mode::Outbound => outbound::run(config).await?,
    }

    Ok(())
}
