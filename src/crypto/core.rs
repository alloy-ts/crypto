//! Master-key handling and deterministic Ed25519/X25519 identity derivation.

use super::error::{CryptoError, CryptoResult};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_PURPOSE_BYTES: usize = 4096;
const IDENTITY_VERSION: u32 = 1;
const SIGNING_DOMAIN_V1: &[u8] = b"alloy/master/ed25519/v1";
const ENCRYPTION_DOMAIN_V1: &[u8] = b"alloy/master/x25519/v1";

pub type CoreError = CryptoError;
pub type CoreResult<T> = CryptoResult<T>;

/// A high-entropy 32-byte root secret.
///
/// Generate it once and keep it in secure storage. A password is not a master
/// key and must be strengthened separately before use here.
#[napi]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; 32],
}

/// Domain-separated Ed25519 and X25519 keys derived from one identity context.
///
/// Secret-key serialization is intentionally unavailable. The private keys are
/// used through operations on this value and are zeroized by their key types.
pub struct IdentityKeys {
    signing: SigningKey,
    encryption: StaticSecret,
}

fn validate_purpose(purpose: &str) -> CoreResult<()> {
    if purpose.is_empty() || purpose.len() > MAX_PURPOSE_BYTES {
        return Err(CoreError::InvalidPurpose);
    }
    Ok(())
}

fn derive_seed(master: &[u8; 32], domain: &[u8], purpose: &str) -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(domain), master)
        .expand(purpose.as_bytes(), seed.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    seed
}

impl MasterKey {
    /// Generate a new master key with the operating system CSPRNG.
    pub fn generate() -> CoreResult<Self> {
        let mut bytes = [0; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| CoreError::RandomFailure)?;
        Ok(Self { bytes })
    }

    /// Import an existing 32-byte master secret.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Reproduce a domain-separated signing and encryption identity.
    ///
    /// Version 1 preserves the derivation protocol shipped by the original
    /// Node API. Unknown versions fail instead of silently creating keys under
    /// an undefined protocol.
    pub fn derive_identity(&self, purpose: &str, version: u32) -> CoreResult<IdentityKeys> {
        validate_purpose(purpose)?;
        if version != IDENTITY_VERSION {
            return Err(CoreError::UnsupportedVersion);
        }

        let signing_seed = derive_seed(&self.bytes, SIGNING_DOMAIN_V1, purpose);
        let encryption_seed = derive_seed(&self.bytes, ENCRYPTION_DOMAIN_V1, purpose);
        Ok(IdentityKeys {
            signing: SigningKey::from_bytes(&signing_seed),
            encryption: StaticSecret::from(*encryption_seed),
        })
    }
}

impl IdentityKeys {
    pub fn signing_public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn encryption_public_key(&self) -> [u8; 32] {
        X25519PublicKey::from(&self.encryption).to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    pub(crate) fn encryption_secret(&self) -> &StaticSecret {
        &self.encryption
    }
}

#[napi]
impl MasterKey {
    #[napi(constructor)]
    pub fn new(bytes: Buffer) -> napi::Result<Self> {
        let bytes = bytes
            .as_ref()
            .try_into()
            .map_err(|_| napi::Error::from_reason("expected 32-byte master secret"))?;
        Ok(Self::from_bytes(bytes))
    }

    #[napi(factory, js_name = "generate")]
    pub fn generate_node() -> napi::Result<Self> {
        Self::generate().map_err(Into::into)
    }

    #[napi]
    pub fn encryption_public_key(&self, purpose: String) -> napi::Result<Buffer> {
        Ok(self
            .derive_identity(&purpose, IDENTITY_VERSION)
            .map_err(napi::Error::from)?
            .encryption_public_key()
            .to_vec()
            .into())
    }

    #[napi]
    pub fn signing_public_key(&self, purpose: String) -> napi::Result<Buffer> {
        Ok(self
            .derive_identity(&purpose, IDENTITY_VERSION)
            .map_err(napi::Error::from)?
            .signing_public_key()
            .to_vec()
            .into())
    }

    #[napi]
    pub fn sign_child(&self, purpose: String, message: Buffer) -> napi::Result<Buffer> {
        Ok(self
            .derive_identity(&purpose, IDENTITY_VERSION)
            .map_err(napi::Error::from)?
            .sign(&message)
            .to_vec()
            .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn deterministic_golden_identity_is_stable() {
        let master = MasterKey::from_bytes([42; 32]);
        let first = master.derive_identity("repo:1", 1).unwrap();
        let second = master.derive_identity("repo:1", 1).unwrap();

        assert_eq!(first.signing_public_key(), second.signing_public_key());
        assert_eq!(
            first.encryption_public_key(),
            second.encryption_public_key()
        );
        assert_eq!(
            first.signing_public_key(),
            [
                0x03, 0x12, 0x2f, 0x9d, 0x80, 0x5e, 0x9a, 0x24, 0x22, 0x1d, 0x89, 0xf7, 0x01, 0x50,
                0xf2, 0x14, 0x7a, 0xf5, 0xfc, 0xf6, 0xcc, 0x5d, 0xc0, 0xe5, 0x59, 0xe7, 0xfe, 0xce,
                0xa8, 0x06, 0xee, 0x90,
            ]
        );
        assert_eq!(
            first.encryption_public_key(),
            [
                0xa1, 0x75, 0x9a, 0x3d, 0x98, 0x1c, 0xfc, 0xa2, 0x7e, 0x3d, 0xe5, 0xbb, 0x81, 0xf3,
                0x1b, 0x81, 0xdb, 0x50, 0x56, 0x65, 0x5a, 0xcd, 0x93, 0xdd, 0xd1, 0xba, 0xca, 0x9a,
                0xf7, 0x05, 0xd3, 0x22,
            ]
        );
    }

    #[test]
    fn contexts_and_key_types_are_separated() {
        let master = MasterKey::from_bytes([7; 32]);
        let repository = master.derive_identity("repo:1", 1).unwrap();
        let device = master.derive_identity("device:1", 1).unwrap();
        assert_ne!(repository.signing_public_key(), device.signing_public_key());
        assert_ne!(
            repository.encryption_public_key(),
            device.encryption_public_key()
        );
        assert_ne!(
            repository.signing_public_key(),
            repository.encryption_public_key()
        );
    }

    #[test]
    fn signatures_verify_and_invalid_parameters_fail() {
        let master = MasterKey::from_bytes([9; 32]);
        let identity = master.derive_identity("device:1", 1).unwrap();
        let message = b"message";
        let signature = Signature::from_bytes(&identity.sign(message));
        VerifyingKey::from_bytes(&identity.signing_public_key())
            .unwrap()
            .verify(message, &signature)
            .unwrap();

        assert!(matches!(
            master.derive_identity("", 1),
            Err(CoreError::InvalidPurpose)
        ));
        assert!(matches!(
            master.derive_identity("repo:1", 2),
            Err(CoreError::UnsupportedVersion)
        ));
    }

    #[test]
    fn generated_master_keys_are_distinct() {
        let first = MasterKey::generate().unwrap();
        let second = MasterKey::generate().unwrap();
        assert_ne!(
            first
                .derive_identity("identity", 1)
                .unwrap()
                .signing_public_key(),
            second
                .derive_identity("identity", 1)
                .unwrap()
                .signing_public_key()
        );
    }
}
