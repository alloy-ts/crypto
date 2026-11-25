//! Version 1 envelope protocol. Context must be supplied by the trusted caller.
use super::core::{IdentityKeys, MasterKey};
use super::error::{CryptoError, CryptoResult};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

const SUITE: &str = "alloy-envelope-v1/x25519-hkdf-sha256-xchacha20poly1305-hmacsha256";
const MAX_DATA: usize = 16 * 1024 * 1024;
const MAX_JSON: usize = 80 * 1024 * 1024;
const MAX_RECIPIENTS: usize = 256;

fn random<const N: usize>() -> CryptoResult<[u8; N]> {
    let mut bytes = [0; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CryptoError::RandomFailure)?;
    Ok(bytes)
}

// Fixed ordering and length prefixes make the authenticated transcript unambiguous.
fn transcript(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn derive(secret: &[u8], label: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(label), secret)
        .expand(info, out.as_mut())
        .expect("valid HKDF output length");
    out
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Slot {
    id: [u8; 32],
    ephemeral: [u8; 32],
    nonce: [u8; 24],
    wrapped: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    suite: String,
    context: String,
    recipients: Vec<Slot>,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    tag: [u8; 32],
}

pub(crate) fn recipient_id(public: &PublicKey) -> [u8; 32] {
    Sha256::digest(transcript(&[b"alloy/recipient/v1", public.as_bytes()])).into()
}

fn context_check(context: &str) -> CryptoResult<()> {
    if context.is_empty() || context.len() > 4096 {
        return Err(CryptoError::InvalidContext);
    }
    Ok(())
}

impl Envelope {
    fn aad(&self) -> Vec<u8> {
        transcript(&[
            SUITE.as_bytes(),
            &self.version.to_be_bytes(),
            self.context.as_bytes(),
        ])
    }

    fn header(&self) -> Vec<u8> {
        let mut parts = vec![self.aad(), self.nonce.to_vec(), self.ciphertext.clone()];
        for slot in &self.recipients {
            parts.push(transcript(&[
                &slot.id,
                &slot.ephemeral,
                &slot.nonce,
                &slot.wrapped,
            ]));
        }
        transcript(&parts.iter().map(Vec::as_slice).collect::<Vec<_>>())
    }

    fn mac(&self, dek: &[u8]) -> Hmac<Sha256> {
        let key = derive(dek, b"alloy/envelope/header-mac/v1", &self.aad());
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_ref()).unwrap();
        mac.update(&self.header());
        mac
    }

    fn authenticate(&mut self, dek: &[u8]) {
        self.tag = self.mac(dek).finalize().into_bytes().into();
    }

    fn decode(json: &str) -> CryptoResult<Self> {
        if json.len() > MAX_JSON {
            return Err(CryptoError::EnvelopeTooLarge);
        }
        let env: Self =
            serde_json::from_str(json).map_err(|_| CryptoError::InvalidEnvelopeEncoding)?;
        if env.version != 1 || env.suite != SUITE {
            return Err(CryptoError::UnsupportedEnvelopeProtocol);
        }
        context_check(&env.context)?;
        if env.ciphertext.len() < 16
            || env.ciphertext.len() > MAX_DATA + 16
            || env.recipients.is_empty()
            || env.recipients.len() > MAX_RECIPIENTS
            || env.recipients.iter().any(|s| s.wrapped.len() != 48)
            || env.recipients.windows(2).any(|s| s[0].id >= s[1].id)
        {
            return Err(CryptoError::InvalidEnvelopeStructure);
        }
        Ok(env)
    }

    fn parse(json: &str, expected: &str) -> CryptoResult<Self> {
        context_check(expected)?;
        let env = Self::decode(json)?;
        if env.context != expected {
            return Err(CryptoError::ContextMismatch);
        }
        Ok(env)
    }

    fn unwrap(&self, secret: &StaticSecret) -> CryptoResult<Zeroizing<[u8; 32]>> {
        let public = PublicKey::from(secret);
        let slot = self
            .recipients
            .iter()
            .find(|s| s.id == recipient_id(&public))
            .ok_or(CryptoError::DecryptionFailed)?;
        let shared = secret.diffie_hellman(&PublicKey::from(slot.ephemeral));
        if !shared.was_contributory() {
            return Err(CryptoError::DecryptionFailed);
        }
        let aad = transcript(&[&self.aad(), &slot.id, &slot.ephemeral, public.as_bytes()]);
        let kek = derive(shared.as_bytes(), b"alloy/envelope/wrap/v1", &aad);
        let cipher = XChaCha20Poly1305::new_from_slice(kek.as_ref()).unwrap();
        let bytes = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&slot.nonce),
                    Payload {
                        msg: &slot.wrapped,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptoError::DecryptionFailed)?,
        );
        if bytes.len() != 32 {
            return Err(CryptoError::DecryptionFailed);
        }
        let mut dek = Zeroizing::new([0; 32]);
        dek.copy_from_slice(&bytes);
        self.mac(dek.as_ref())
            .verify_slice(&self.tag)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(dek)
    }

    fn wrap(&self, dek: &[u8], public: &PublicKey) -> CryptoResult<Slot> {
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let eph = PublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(public);
        if !shared.was_contributory() {
            return Err(CryptoError::InvalidPublicKey);
        }
        let recipient = recipient_id(public);
        let aad = transcript(&[&self.aad(), &recipient, eph.as_bytes(), public.as_bytes()]);
        let kek = derive(shared.as_bytes(), b"alloy/envelope/wrap/v1", &aad);
        let nonce = random()?;
        let wrapped = XChaCha20Poly1305::new_from_slice(kek.as_ref())
            .unwrap()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: dek,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(Slot {
            id: recipient,
            ephemeral: *eph.as_bytes(),
            nonce,
            wrapped,
        })
    }

    fn seal(context: &str, plaintext: &[u8], recipients: &[[u8; 32]]) -> CryptoResult<Self> {
        context_check(context)?;
        if plaintext.len() > MAX_DATA {
            return Err(CryptoError::PlaintextTooLarge);
        }
        if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
            return Err(CryptoError::InvalidRecipientCount);
        }
        let dek = Zeroizing::new(random::<32>()?);
        let mut env = Self {
            version: 1,
            suite: SUITE.into(),
            context: context.into(),
            recipients: vec![],
            nonce: random()?,
            ciphertext: vec![],
            tag: [0; 32],
        };
        for public in recipients {
            env.recipients
                .push(env.wrap(dek.as_ref(), &PublicKey::from(*public))?);
        }
        env.recipients.sort_by_key(|s| s.id);
        if env.recipients.windows(2).any(|s| s[0].id == s[1].id) {
            return Err(CryptoError::DuplicateRecipient);
        }
        env.ciphertext = XChaCha20Poly1305::new_from_slice(dek.as_ref())
            .unwrap()
            .encrypt(
                XNonce::from_slice(&env.nonce),
                Payload {
                    msg: plaintext,
                    aad: &env.aad(),
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;
        env.authenticate(dek.as_ref());
        Ok(env)
    }

    fn open(&self, secret: &StaticSecret) -> CryptoResult<Vec<u8>> {
        let dek = self.unwrap(secret)?;
        XChaCha20Poly1305::new_from_slice(dek.as_ref())
            .unwrap()
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &self.aad(),
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

pub(crate) fn envelope_recipient_ids(json: &str) -> CryptoResult<Vec<[u8; 32]>> {
    Ok(Envelope::decode(json)?
        .recipients
        .into_iter()
        .map(|slot| slot.id)
        .collect())
}

fn api<T>(value: CryptoResult<T>) -> napi::Result<T> {
    value.map_err(Into::into)
}
fn public_keys(keys: Vec<Buffer>) -> napi::Result<Vec<[u8; 32]>> {
    keys.iter()
        .map(|key| {
            key.as_ref()
                .try_into()
                .map_err(|_| napi::Error::from_reason("expected 32-byte public key"))
        })
        .collect()
}
fn json(env: &Envelope) -> napi::Result<String> {
    serde_json::to_string(env).map_err(|_| CryptoError::SerializationFailed.into())
}

impl MasterKey {
    fn envelope_identity(&self, purpose: &str) -> napi::Result<IdentityKeys> {
        self.derive_identity(purpose, 1).map_err(Into::into)
    }
}

#[napi]
impl MasterKey {
    #[napi]
    pub fn open(
        &self,
        purpose: String,
        expected_context: String,
        envelope: String,
    ) -> napi::Result<Buffer> {
        let env = api(Envelope::parse(&envelope, &expected_context))?;
        let identity = self.envelope_identity(&purpose)?;
        Ok(api(env.open(identity.encryption_secret()))?.into())
    }
    /// Every existing recipient can delegate. Application policy must enforce admin rules.
    #[napi]
    pub fn add_recipient(
        &self,
        purpose: String,
        expected_context: String,
        envelope: String,
        public_key: Buffer,
    ) -> napi::Result<String> {
        let mut env = api(Envelope::parse(&envelope, &expected_context))?;
        let identity = self.envelope_identity(&purpose)?;
        let dek = api(env.unwrap(identity.encryption_secret()))?;
        let keys = public_keys(vec![public_key])?;
        let slot = api(env.wrap(dek.as_ref(), &PublicKey::from(keys[0])))?;
        if env.recipients.iter().any(|s| s.id == slot.id) {
            return Err(CryptoError::DuplicateRecipient.into());
        }
        if env.recipients.len() >= MAX_RECIPIENTS {
            return Err(CryptoError::TooManyRecipients.into());
        }
        env.recipients.push(slot);
        env.recipients.sort_by_key(|s| s.id);
        env.authenticate(dek.as_ref());
        json(&env)
    }
    /// Re-encrypts with a new DEK. Does not revoke access to historical copies.
    #[napi]
    pub fn rotate_recipients(
        &self,
        purpose: String,
        expected_context: String,
        envelope: String,
        recipients: Vec<Buffer>,
    ) -> napi::Result<String> {
        let env = api(Envelope::parse(&envelope, &expected_context))?;
        let identity = self.envelope_identity(&purpose)?;
        let plain = Zeroizing::new(api(env.open(identity.encryption_secret()))?);
        json(&api(Envelope::seal(
            &expected_context,
            &plain,
            &public_keys(recipients)?,
        ))?)
    }
}

#[napi]
pub fn seal_envelope(
    context: String,
    plaintext: Buffer,
    recipients: Vec<Buffer>,
) -> napi::Result<String> {
    json(&api(Envelope::seal(
        &context,
        &plaintext,
        &public_keys(recipients)?,
    ))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_headers_and_bounds() {
        let secret = StaticSecret::from([1; 32]);
        let public = PublicKey::from(&secret).to_bytes();
        let env = Envelope::seal("ctx", b"", &[public]).unwrap();
        assert_eq!(env.open(&secret).unwrap(), b"");
        for field in 0..6 {
            let mut bad = env.clone();
            match field {
                0 => bad.version = 2,
                1 => bad.suite = "unknown".into(),
                2 => bad.recipients[0].wrapped.clear(),
                3 => bad.ciphertext.clear(),
                4 => bad.recipients.clear(),
                _ => bad.context = "other".into(),
            }
            assert!(Envelope::parse(&serde_json::to_string(&bad).unwrap(), "ctx").is_err());
        }
        let encoded = serde_json::to_string(&env).unwrap();
        assert!(Envelope::parse(&encoded.replacen('{', "{\"extra\":0,", 1), "ctx").is_err());
        assert!(Envelope::parse(&encoded.replacen('{', "{\"version\":1,", 1), "ctx").is_err());
        assert!(Envelope::seal("", b"x", &[public]).is_err());
        assert!(Envelope::seal(&"x".repeat(4097), b"x", &[public]).is_err());
        assert!(Envelope::seal("ctx", &vec![0; MAX_DATA + 1], &[public]).is_err());
        assert!(Envelope::seal("ctx", b"x", &vec![public; MAX_RECIPIENTS + 1]).is_err());
        let mut bad = env.clone();
        bad.recipients[0].ephemeral = [0; 32];
        assert!(bad.open(&secret).is_err());
        bad = env.clone();
        bad.recipients[0].id[0] ^= 1;
        assert!(bad.open(&secret).is_err());
    }

    #[test]
    fn recipients_context_rotation_and_tampering() {
        let alice = StaticSecret::from([1; 32]);
        let bob = StaticSecret::from([2; 32]);
        let carol = StaticSecret::from([3; 32]);
        let pubs = [
            PublicKey::from(&alice).to_bytes(),
            PublicKey::from(&bob).to_bytes(),
        ];
        let env = Envelope::seal("repo:1/file", b"secret", &pubs).unwrap();
        assert_eq!(env.open(&alice).unwrap(), b"secret");
        assert_eq!(env.open(&bob).unwrap(), b"secret");
        assert!(env.open(&carol).is_err());
        let encoded = serde_json::to_string(&env).unwrap();
        assert!(Envelope::parse(&encoded, "repo:2/file").is_err());
        assert!(Envelope::parse(&encoded, "repo:1/file").is_ok());
        for field in 0..7 {
            let mut bad = env.clone();
            match field {
                0 => bad.ciphertext[0] ^= 1,
                1 => bad.nonce[0] ^= 1,
                2 => bad.recipients[0].wrapped[0] ^= 1,
                3 => bad.recipients[0].ephemeral[0] ^= 1,
                4 => bad.recipients[0].nonce[0] ^= 1,
                5 => {
                    bad.recipients.pop();
                }
                _ => bad.tag[0] ^= 1,
            }
            assert!(bad.open(&alice).is_err(), "mutation {field}");
        }
        let mut added = env.clone();
        let dek = added.unwrap(&alice).unwrap();
        added
            .recipients
            .push(added.wrap(dek.as_ref(), &PublicKey::from(&carol)).unwrap());
        added.recipients.sort_by_key(|s| s.id);
        added.authenticate(dek.as_ref());
        assert_eq!(added.ciphertext, env.ciphertext);
        assert_eq!(added.open(&carol).unwrap(), b"secret");
        let rotated = Envelope::seal(&env.context, &env.open(&alice).unwrap(), &[pubs[0]]).unwrap();
        assert!(rotated.open(&bob).is_err());
        assert_eq!(rotated.open(&alice).unwrap(), b"secret");
        assert_ne!(rotated.ciphertext, env.ciphertext);
        assert!(Envelope::seal("ctx", b"x", &[[0; 32]]).is_err());
        assert!(Envelope::seal("ctx", b"x", &[pubs[0], pubs[0]]).is_err());
        assert!(Envelope::seal("ctx", b"x", &[]).is_err());
        let mut bad = env.clone();
        bad.recipients.push(bad.recipients[0].clone());
        assert!(Envelope::parse(&serde_json::to_string(&bad).unwrap(), &env.context).is_err());
        assert!(Envelope::parse("{}", &env.context).is_err());
    }
}
