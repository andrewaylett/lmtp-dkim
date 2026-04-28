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

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
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
pub enum Mode {
    /// Accept mail from the Internet, validate, ARC-seal, and forward.
    Inbound,
    /// Accept mail from users, DKIM-sign, and forward.
    Outbound,
}

/// How and where to listen for incoming LMTP connections.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ListenConfig {
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

fn default_socket_mode() -> u32 {
    0o600
}

/// Where to deliver processed mail.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DownstreamConfig {
    /// Deliver to a Unix-socket LMTP server (e.g. Dovecot).
    UnixSocket {
        /// Path to the downstream LMTP socket.
        socket: PathBuf,
    },
    /// Deliver to a TCP LMTP or SMTP server.
    Tcp {
        /// Hostname of the downstream server.
        host: String,
        /// Port (25 for SMTP, 24 for LMTP over TCP).
        port: u16,
    },
}

/// ARC signing configuration (inbound mode).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArcConfig {
    /// `d=` domain for ARC-Seal and ARC-Message-Signature.
    pub domain: String,

    /// `s=` selector.
    pub selector: String,

    /// Path to the PEM-encoded private key file.
    ///
    /// Accepted formats: PKCS#8 RSA or Ed25519. Ed25519 is recommended.
    pub key_file: PathBuf,

    /// The authentication service identifier to use in
    /// `ARC-Authentication-Results`. Typically the MX hostname.
    pub authserv_id: String,

    /// Header fields to include in the ARC-Message-Signature `h=` list
    /// beyond the required `ARC-Authentication-Results` and `From:`.
    ///
    /// Default matches the DKIM recommended list.
    #[serde(default = "default_signed_headers")]
    pub signed_headers: Vec<String>,
}

/// DKIM signing configuration for one domain (outbound mode).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DkimSigningConfig {
    /// `d=` domain.
    pub domain: String,

    /// `s=` selector.
    pub selector: String,

    /// Path to the PEM-encoded private key file.
    pub key_file: PathBuf,

    /// Header fields to sign.
    #[serde(default = "default_signed_headers")]
    pub signed_headers: Vec<String>,

    /// Signature expiry in seconds from the time of signing.
    ///
    /// `None` means no expiry. Recommended: 604800 (7 days).
    #[serde(default)]
    pub expiry_secs: Option<u64>,
}

/// Miscellaneous server settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerSettings {
    /// Server hostname to announce in LMTP `220` greetings.
    ///
    /// Defaults to the system hostname.
    #[serde(default)]
    pub hostname: Option<String>,

    /// Maximum accepted message size in bytes.
    ///
    /// Defaults to 50 MiB.
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            hostname: None,
            max_message_size: default_max_message_size(),
        }
    }
}

fn default_max_message_size() -> usize {
    50 * 1024 * 1024
}

fn default_signed_headers() -> Vec<String> {
    vec![
        "from".into(),
        "from".into(), // over-signing
        "to".into(),
        "to".into(),   // over-signing
        "cc".into(),
        "subject".into(),
        "date".into(),
        "reply-to".into(),
        "message-id".into(),
        "content-type".into(),
        "mime-version".into(),
    ]
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// If `path` is `None`, tries `LMTP_DKIM_CONFIG` env var, then
    /// `/etc/lmtp-dkim/config.toml`.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let default_path = PathBuf::from("/etc/lmtp-dkim/config.toml");
        let effective_path = path.unwrap_or(&default_path);
        let raw = std::fs::read_to_string(effective_path)?;
        let config: Config = toml::from_str(&raw)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate that required fields for the chosen mode are present.
    pub fn validate(&self) -> anyhow::Result<()> {
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
