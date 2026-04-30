use super::default_max_message_size;
use serde::{Deserialize, Serialize};

/// Miscellaneous server settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ServerSettings {
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
