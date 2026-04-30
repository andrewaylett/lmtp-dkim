//! Configuration schema for the `lmtp-dkim` service.
//!
//! Configuration is loaded from a TOML file. The default path is
//! `/etc/lmtp-dkim/config.toml`, overridden by the `--config` flag or the
//! `LMTP_DKIM_CONFIG` environment variable.
//!
//! # Minimal inbound config
//!
//! ```toml
//! mode = "inbound"
//!
//! [listen]
//! socket = "/run/lmtp-dkim/inbound.sock"
//!
//! [downstream]
//! socket = "/run/dovecot/lmtp"
//!
//! [arc]
//! domain   = "example.com"
//! selector = "arc2024"
//! key_file = "/etc/lmtp-dkim/arc.pem"
//! authserv_id = "mx.example.com"
//! ```
//!
//! # Minimal outbound config
//!
//! ```toml
//! mode = "outbound"
//!
//! [listen]
//! socket = "/run/lmtp-dkim/outbound.sock"
//!
//! [downstream]
//! host = "relay.example.com"
//! port = 25
//!
//! [[dkim]]
//! domain   = "example.com"
//! selector = "dkim2024"
//! key_file = "/etc/lmtp-dkim/dkim.pem"
//! ```

mod arc;
mod dkim_signing;
mod downstream;
mod server_settings;

use std::path::{Path, PathBuf};

use arc::ArcConfig;
use dkim_signing::DkimSigningConfig;
use downstream::DownstreamConfig;
use serde::{Deserialize, Serialize};
use server_settings::ServerSettings;

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Config {
    /// Operating mode.
    pub mode: Mode,

    /// LMTP listener configuration.
    pub listen: ListenConfig,

    /// Downstream LMTP/SMTP delivery configuration.
    pub downstream: DownstreamConfig,

    /// ARC signing configuration (required for `inbound` mode).
    #[serde(default)]
    pub arc: Option<ArcConfig>,

    /// DKIM signing configurations (required for `outbound` mode; may have
    /// multiple entries for different domains).
    #[serde(default)]
    pub dkim: Vec<DkimSigningConfig>,

    /// Server settings.
    #[serde(default)]
    pub server: ServerSettings,
}

/// Operating mode of the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Mode {
    /// Accept mail from the Internet, validate, ARC-seal, and forward.
    Inbound,
    /// Accept mail from users, DKIM-sign, and forward.
    Outbound,
}

/// How and where to listen for incoming LMTP connections.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum ListenConfig {
    /// Listen on a Unix domain socket.
    UnixSocket {
        /// Path to the socket file.
        socket: PathBuf,
        /// Socket permissions (octal). Defaults to `0o600`.
        #[serde(default = "default_socket_mode")]
        mode: u32,
    },
    /// Listen on a TCP address.
    Tcp {
        /// Bind address, e.g. `"127.0.0.1"`.
        host: String,
        /// TCP port.
        port: u16,
    },
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// If `path` is `None`, tries `LMTP_DKIM_CONFIG` env var, then
    /// `/etc/lmtp-dkim/config.toml`.
    pub(crate) fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let default_path = PathBuf::from("/etc/lmtp-dkim/config.toml");
        let effective_path = path.unwrap_or(&default_path);
        let raw = std::fs::read_to_string(effective_path)?;
        let config: Self = toml::from_str(&raw)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate that required fields for the chosen mode are present.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        match self.mode {
            Mode::Inbound => {
                anyhow::ensure!(
                    self.arc.is_some(),
                    "inbound mode requires an [arc] configuration section"
                );
            }
            Mode::Outbound => {
                anyhow::ensure!(
                    !self.dkim.is_empty(),
                    "outbound mode requires at least one [[dkim]] configuration section"
                );
            }
        }
        Ok(())
    }
}

const fn default_socket_mode() -> u32 {
    0o600
}

const fn default_max_message_size() -> usize {
    50 * 1024 * 1024
}

fn default_signed_headers() -> Vec<String> {
    vec![
        "from".into(),
        "from".into(), // over-signing
        "to".into(),
        "to".into(), // over-signing
        "cc".into(),
        "subject".into(),
        "date".into(),
        "reply-to".into(),
        "message-id".into(),
        "content-type".into(),
        "mime-version".into(),
    ]
}
