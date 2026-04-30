use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Where to deliver processed mail.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum DownstreamConfig {
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
