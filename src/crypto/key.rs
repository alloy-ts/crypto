use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use napi::bindgen_prelude::{Buffer, Either};
use napi_derive::napi;
use slip10::{Curve, Key};

/// A deterministic ed25519 key pair derived from a seed via SLIP-0010.
///
/// The seed may be supplied as a UTF-8 string or as raw bytes (Buffer). The
/// key pair is derived from the seed using the SLIP-0010 master path ("m")
/// for the ed25519 curve, which is hardened-only as required by SLIP-0010, so
/// the same seed always yields the same ed25519 key pair.
#[napi]
pub struct CryptoKey {
    signing_key: SigningKey,
    chain_code: [u8; 32],
}

/// Derive an ed25519 signing key from a seed using SLIP-0010 (ed25519, master
/// path). The 32-byte SLIP-0010 secret is the RFC 8032 ed25519 seed, so it can
/// be fed directly into `SigningKey::from_bytes`.
fn derive_ed25519(seed: &[u8]) -> (SigningKey, [u8; 32]) {
    let master: Key = Key::new(seed, Curve::Ed25519);
    let signing_key = SigningKey::from_bytes(&master.key);
    (signing_key, master.chain_code)
}

#[napi]
impl CryptoKey {
    /// Create a new ed25519 key pair from a seed.
    ///
    /// `seed` accepts either a string (interpreted as UTF-8 bytes) or a Buffer
    /// of raw bytes. The same seed always produces the same key pair.
    #[napi(constructor)]
    pub fn new(seed: Either<String, Buffer>) -> napi::Result<Self> {
        let seed_bytes: Vec<u8> = match seed {
            Either::A(s) => s.into_bytes(),
            Either::B(b) => b.to_vec(),
        };
        let (signing_key, chain_code) = derive_ed25519(&seed_bytes);
        Ok(Self {
            signing_key,
            chain_code,
        })
    }

    /// The 32-byte ed25519 public key.
    #[napi]
    pub fn public_key(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    /// The 32-byte SLIP-0010 chain code for this derived key.
    #[napi]
    pub fn chain_code(&self) -> Vec<u8> {
        self.chain_code.to_vec()
    }

    /// Sign a message, returning the 64-byte ed25519 signature.
    #[napi]
    pub fn sign(&self, message: Buffer) -> Vec<u8> {
        let signature = self.signing_key.sign(message.as_ref());
        signature.to_bytes().to_vec()
    }

    /// Verify a 64-byte ed25519 signature over a message.
    #[napi]
    pub fn verify(&self, message: Buffer, signature: Buffer) -> bool {
        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        match ed25519_dalek::Signature::from_slice(signature.as_ref()) {
            Ok(sig) => verifying_key.verify(message.as_ref(), &sig).is_ok(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_seed() {
        let a = derive_ed25519(b"hello world");
        let b = derive_ed25519(b"hello world");
        assert_eq!(a.0.verifying_key(), b.0.verifying_key());
    }

    #[test]
    fn string_and_bytes_seed_agree() {
        // A string seed and its UTF-8 byte form must derive the same key.
        let from_str = CryptoKey::new(Either::A("hello world".to_string())).unwrap();
        let from_bytes = CryptoKey::new(Either::B(Buffer::from(b"hello world".to_vec()))).unwrap();
        assert_eq!(from_str.public_key(), from_bytes.public_key());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = CryptoKey::new(Either::A("test-seed".to_string())).unwrap();
        let msg = b"sign me".to_vec();
        let sig = key.sign(Buffer::from(msg.clone()));
        assert!(key.verify(Buffer::from(msg.clone()), Buffer::from(sig.clone())));
        // Tampered message must fail verification.
        assert!(!key.verify(Buffer::from(b"other".to_vec()), Buffer::from(sig)));
    }
}
