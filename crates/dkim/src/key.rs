//! Cryptographic key types for DKIM signing and verification.
//!
//! We use the [`ring`] crate for all cryptographic operations because it is
//! widely audited, has no unsafe code exposed to callers, and supports both
//! RSA-PKCS1v15 and Ed25519 natively.
//!
//! # Key representations
//!
//! | Algorithm | Private key format | Public key format |
//! |-----------|-------------------|------------------|
//! | RSA | PKCS#8 DER | `SubjectPublicKeyInfo` DER |
//! | Ed25519 | PKCS#8 DER (seed) | 32 raw bytes |
//!
//! Both formats are base64-encoded in the config file and DNS TXT records
//! respectively.
//!
//! # Key rotation
//!
//! DKIM keys should be rotated periodically (recommendation: every 6 months).
//! The `s=` selector enables simultaneous existence of multiple keys: the
//! old selector remains valid for messages already in transit while the new
//! selector is used for fresh signatures. Retire the old selector once its
//! TTL has elapsed and any in-transit mail has been delivered.

#[expect(
    unused_imports,
    reason = "stub: Error variants referenced when implemented"
)]
use crate::Error;
use crate::Result;

/// A DKIM private key, used for signing.
///
/// Wraps the `ring` key material. Key material is zeroed on drop by `ring`.
pub enum PrivateKey {
    /// RSA private key. Minimum 2048-bit recommended (RFC 8301).
    Rsa(ring::signature::RsaKeyPair),
    /// Ed25519 private key.
    Ed25519(ring::signature::Ed25519KeyPair),
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => f.write_str("PrivateKey::Rsa(...)"),
            Self::Ed25519(_) => f.write_str("PrivateKey::Ed25519(...)"),
        }
    }
}

impl PrivateKey {
    /// Load an RSA private key from PKCS#8 DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::KeyDecode`] if the DER bytes are malformed.
    pub fn rsa_from_pkcs8_der(_der: &[u8]) -> Result<Self> {
        todo!("ring::signature::RsaKeyPair::from_pkcs8(der).map_err(...)")
    }

    /// Load an Ed25519 private key from PKCS#8 DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::KeyDecode`] if the DER bytes are malformed.
    pub fn ed25519_from_pkcs8_der(_der: &[u8]) -> Result<Self> {
        todo!("ring::signature::Ed25519KeyPair::from_pkcs8(der).map_err(...)")
    }

    /// Load a private key from a PEM-encoded file (auto-detects RSA vs Ed25519
    /// from the PEM type header).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::KeyDecode`] if the file cannot be read or
    /// the key bytes are malformed.
    pub fn from_pem_file(_path: &std::path::Path) -> Result<Self> {
        todo!(
            "read PEM; strip headers; base64-decode; \
             try Ed25519KeyPair first, then RsaKeyPair; \
             return Error::KeyDecode if neither succeeds"
        )
    }

    /// Sign `data` using the appropriate algorithm.
    ///
    /// Returns the raw signature bytes. The caller is responsible for
    /// base64-encoding the result for the `b=` tag.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the signing operation fails.
    pub fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
        todo!(
            "Rsa: ring::signature::RsaKeyPair::sign(&RSA_PKCS1_SHA256, rng, data, sig); \
             Ed25519: ring::signature::Ed25519KeyPair::sign(data)"
        )
    }

    /// The algorithm tag (`a=`) for the `DKIM-Signature` header.
    #[must_use]
    pub const fn algorithm(&self) -> crate::signature::Algorithm {
        match self {
            Self::Rsa(_) => crate::signature::Algorithm::RsaSha256,
            Self::Ed25519(_) => crate::signature::Algorithm::Ed25519Sha256,
        }
    }
}

/// A DKIM public key, used for verification.
///
/// Constructed from DNS TXT record data by [`crate::dns::DkimDnsRecord`].
pub enum PublicKey {
    /// RSA public key.
    Rsa(ring::signature::UnparsedPublicKey<Vec<u8>>),
    /// Ed25519 public key.
    Ed25519(ring::signature::UnparsedPublicKey<Vec<u8>>),
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => f.write_str("PublicKey::Rsa(...)"),
            Self::Ed25519(_) => f.write_str("PublicKey::Ed25519(...)"),
        }
    }
}

impl PublicKey {
    /// Verify a signature over `data`.
    ///
    /// Returns `Ok(())` on success, [`crate::Error::SignatureMismatch`] on failure.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::SignatureMismatch`] if the signature is invalid.
    pub fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<()> {
        todo!(
            "self.inner.verify(data, signature) \
             .map_err(|_| Error::SignatureMismatch)"
        )
    }
}
