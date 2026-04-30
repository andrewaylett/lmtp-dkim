use super::default_signed_headers;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// ARC signing configuration (inbound mode).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ArcConfig {
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
