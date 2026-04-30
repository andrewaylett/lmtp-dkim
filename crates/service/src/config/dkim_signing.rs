use super::default_signed_headers;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// DKIM signing configuration for one domain (outbound mode).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct DkimSigningConfig {
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
