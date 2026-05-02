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
//! TTL has elapsed and any in-flight mail has been delivered.

use base64::Engine as _;

use crate::{Error, Result};

/// A DKIM private key, used for signing.
///
/// Wraps the `ring` key material. Key material is zeroed on drop by `ring`.
#[non_exhaustive]
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
    pub fn rsa_from_pkcs8_der(der: &[u8]) -> Result<Self> {
        ring::signature::RsaKeyPair::from_pkcs8(der)
            .map(Self::Rsa)
            .map_err(|e| Error::KeyDecode(e.to_string()))
    }

    /// Load an Ed25519 private key from PKCS#8 DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::KeyDecode`] if the DER bytes are malformed.
    pub fn ed25519_from_pkcs8_der(der: &[u8]) -> Result<Self> {
        ring::signature::Ed25519KeyPair::from_pkcs8(der)
            .map(Self::Ed25519)
            .map_err(|e| Error::KeyDecode(e.to_string()))
    }

    /// Load a private key from a PEM-encoded file.
    ///
    /// Tries Ed25519 first, then RSA. The PEM body must be a PKCS#8 DER
    /// structure (standard `BEGIN PRIVATE KEY` header).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the file cannot be read.
    /// Returns [`crate::Error::KeyDecode`] if the key bytes are malformed.
    pub fn from_pem_file(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(Error::Io)?;
        let body: String = content
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&body)
            .map_err(|e| Error::KeyDecode(format!("base64 decode: {e}")))?;
        if let Ok(kp) = ring::signature::Ed25519KeyPair::from_pkcs8(&der) {
            return Ok(Self::Ed25519(kp));
        }
        ring::signature::RsaKeyPair::from_pkcs8(&der)
            .map(Self::Rsa)
            .map_err(|e| Error::KeyDecode(format!("neither Ed25519 nor RSA PKCS#8: {e}")))
    }

    /// Sign `data` using the appropriate algorithm.
    ///
    /// Returns the raw signature bytes. The caller is responsible for
    /// base64-encoding the result for the `b=` tag.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the signing operation fails.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Rsa(key) => {
                let rng = ring::rand::SystemRandom::new();
                let mut sig = vec![0u8; key.public().modulus_len()];
                key.sign(&ring::signature::RSA_PKCS1_SHA256, &rng, data, &mut sig)
                    .map_err(|_unspecified| {
                        Error::Io(std::io::Error::other("RSA signing failed"))
                    })?;
                Ok(sig)
            }
            Self::Ed25519(key) => Ok(key.sign(data).as_ref().to_vec()),
        }
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
#[non_exhaustive]
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
    /// Construct an RSA public key from `SubjectPublicKeyInfo` DER bytes.
    #[must_use]
    pub fn rsa(key_bytes: Vec<u8>) -> Self {
        Self::Rsa(ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            key_bytes,
        ))
    }

    /// Construct an Ed25519 public key from raw 32-byte key material.
    #[must_use]
    pub fn ed25519(key_bytes: Vec<u8>) -> Self {
        Self::Ed25519(ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            key_bytes,
        ))
    }

    /// Verify a signature over `data`.
    ///
    /// Returns `Ok(())` on success, [`crate::Error::SignatureMismatch`] on failure.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::SignatureMismatch`] if the signature is invalid.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let result = match self {
            Self::Rsa(key) | Self::Ed25519(key) => key.verify(data, signature),
        };
        result.map_err(|_unspecified| Error::SignatureMismatch)
    }
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair as _;

    use super::{PrivateKey, PublicKey};
    use crate::Error;

    /// Loading garbage bytes returns `KeyDecode`.
    #[test]
    fn rsa_bad_der_rejected() {
        let err = PrivateKey::rsa_from_pkcs8_der(b"notder").expect_err("bad DER");
        assert!(matches!(err, Error::KeyDecode(_)));
    }

    /// Loading garbage bytes returns `KeyDecode`.
    #[test]
    fn ed25519_bad_der_rejected() {
        let err = PrivateKey::ed25519_from_pkcs8_der(b"notder").expect_err("bad DER");
        assert!(matches!(err, Error::KeyDecode(_)));
    }

    /// Ed25519: generate a key pair, sign, and verify successfully.
    #[test]
    fn ed25519_sign_and_verify() {
        let rng = SystemRandom::new();
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519");
        let key_pair =
            ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load ring kp");
        let pub_bytes = key_pair.public_key().as_ref().to_vec();

        let private = PrivateKey::ed25519_from_pkcs8_der(pkcs8.as_ref()).expect("load private");
        let public = PublicKey::ed25519(pub_bytes);

        let message = b"hello DKIM";
        let sig = private.sign(message).expect("sign");
        public.verify(message, &sig).expect("verify ok");
    }

    /// Verification with a wrong message returns `SignatureMismatch`.
    #[test]
    fn ed25519_verify_wrong_message() {
        let rng = SystemRandom::new();
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519");
        let key_pair =
            ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load ring kp");
        let pub_bytes = key_pair.public_key().as_ref().to_vec();

        let private = PrivateKey::ed25519_from_pkcs8_der(pkcs8.as_ref()).expect("load private");
        let public = PublicKey::ed25519(pub_bytes);

        let sig = private.sign(b"original").expect("sign");
        let err = public.verify(b"tampered", &sig).expect_err("should fail");
        assert!(matches!(err, Error::SignatureMismatch));
    }

    /// `algorithm()` returns the correct tag for each key type.
    #[test]
    fn algorithm_tag() {
        let rng = SystemRandom::new();
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519");
        let key = PrivateKey::ed25519_from_pkcs8_der(pkcs8.as_ref()).expect("load");
        assert_eq!(key.algorithm(), crate::signature::Algorithm::Ed25519Sha256);
    }
}
