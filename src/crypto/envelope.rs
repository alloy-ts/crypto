//! Version 1 envelope protocol. Context must be supplied by the trusted caller.
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
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SUITE: &str = "alloy-envelope-v1/x25519-hkdf-sha256-xchacha20poly1305-hmacsha256";
const MAX_DATA: usize = 16 * 1024 * 1024;
const MAX_JSON: usize = 80 * 1024 * 1024;
const MAX_RECIPIENTS: usize = 256;
type Result<T> = std::result::Result<T, &'static str>;

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| "random generator failed")?;
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

fn id(public: &PublicKey) -> [u8; 32] {
    Sha256::digest(transcript(&[b"alloy/recipient/v1", public.as_bytes()])).into()
}

fn context_check(context: &str) -> Result<()> {
    if context.is_empty() || context.len() > 4096 {
        return Err("invalid context length");
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

    fn parse(json: &str, expected: &str) -> Result<Self> {
        context_check(expected)?;
        if json.len() > MAX_JSON {
            return Err("envelope too large");
        }
        let env: Self = serde_json::from_str(json).map_err(|_| "invalid envelope encoding")?;
        if env.version != 1 || env.suite != SUITE {
            return Err("unsupported envelope protocol");
        }
        if env.context != expected {
            return Err("context mismatch");
        }
        if env.ciphertext.len() < 16
            || env.ciphertext.len() > MAX_DATA + 16
            || env.recipients.is_empty()
            || env.recipients.len() > MAX_RECIPIENTS
            || env.recipients.iter().any(|s| s.wrapped.len() != 48)
            || env.recipients.windows(2).any(|s| s[0].id >= s[1].id)
        {
            return Err("invalid envelope structure");
        }
        Ok(env)
    }

    fn unwrap(&self, secret: &StaticSecret) -> Result<Zeroizing<[u8; 32]>> {
        let public = PublicKey::from(secret);
        let slot = self
            .recipients
            .iter()
            .find(|s| s.id == id(&public))
            .ok_or("decryption failed")?;
        let shared = secret.diffie_hellman(&PublicKey::from(slot.ephemeral));
        if !shared.was_contributory() {
            return Err("invalid X25519 public key");
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
                .map_err(|_| "decryption failed")?,
        );
        if bytes.len() != 32 {
            return Err("decryption failed");
        }
        let mut dek = Zeroizing::new([0; 32]);
        dek.copy_from_slice(&bytes);
        self.mac(dek.as_ref())
            .verify_slice(&self.tag)
            .map_err(|_| "decryption failed")?;
        Ok(dek)
    }

    fn wrap(&self, dek: &[u8], public: &PublicKey) -> Result<Slot> {
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let eph = PublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(public);
        if !shared.was_contributory() {
            return Err("invalid X25519 public key");
        }
        let recipient = id(public);
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
            .map_err(|_| "encryption failed")?;
        Ok(Slot {
            id: recipient,
            ephemeral: *eph.as_bytes(),
            nonce,
            wrapped,
        })
    }

    fn seal(context: &str, plaintext: &[u8], recipients: &[[u8; 32]]) -> Result<Self> {
        context_check(context)?;
        if plaintext.len() > MAX_DATA {
            return Err("plaintext too large");
        }
        if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
            return Err("invalid recipient count");
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
            return Err("duplicate recipient");
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
            .map_err(|_| "encryption failed")?;
        env.authenticate(dek.as_ref());
        Ok(env)
    }

    fn open(&self, secret: &StaticSecret) -> Result<Vec<u8>> {
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
            .map_err(|_| "decryption failed")
    }
}

fn api<T>(value: Result<T>) -> napi::Result<T> {
    value.map_err(napi::Error::from_reason)
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
    serde_json::to_string(env).map_err(|_| napi::Error::from_reason("serialization failed"))
}

/// A high-entropy 32-byte root secret. Passwords must be strengthened separately.
#[napi]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; 32],
}

impl MasterKey {
    fn child(&self, domain: &[u8], purpose: &str) -> Result<Zeroizing<[u8; 32]>> {
        context_check(purpose)?;
        Ok(derive(&self.bytes, domain, purpose.as_bytes()))
    }
    fn encryption(&self, purpose: &str) -> Result<StaticSecret> {
        Ok(StaticSecret::from(
            *self.child(b"alloy/master/x25519/v1", purpose)?,
        ))
    }
}

#[napi]
impl MasterKey {
    #[napi(constructor)]
    pub fn new(bytes: Buffer) -> napi::Result<Self> {
        Ok(Self {
            bytes: bytes
                .as_ref()
                .try_into()
                .map_err(|_| napi::Error::from_reason("expected 32-byte master secret"))?,
        })
    }
    #[napi]
    pub fn encryption_public_key(&self, purpose: String) -> napi::Result<Buffer> {
        Ok(PublicKey::from(&api(self.encryption(&purpose))?)
            .as_bytes()
            .to_vec()
            .into())
    }
    #[napi]
    pub fn signing_public_key(&self, purpose: String) -> napi::Result<Buffer> {
        let seed = api(self.child(b"alloy/master/ed25519/v1", &purpose))?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec()
            .into())
    }
    #[napi]
    pub fn sign_child(&self, purpose: String, message: Buffer) -> napi::Result<Buffer> {
        use ed25519_dalek::Signer;
        let seed = api(self.child(b"alloy/master/ed25519/v1", &purpose))?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&seed)
            .sign(&message)
            .to_bytes()
            .to_vec()
            .into())
    }
    #[napi]
    pub fn open(
        &self,
        purpose: String,
        expected_context: String,
        envelope: String,
    ) -> napi::Result<Buffer> {
        let env = api(Envelope::parse(&envelope, &expected_context))?;
        Ok(api(env.open(&api(self.encryption(&purpose))?))?.into())
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
        let dek = api(env.unwrap(&api(self.encryption(&purpose))?))?;
        let keys = public_keys(vec![public_key])?;
        let slot = api(env.wrap(dek.as_ref(), &PublicKey::from(keys[0])))?;
        if env.recipients.iter().any(|s| s.id == slot.id) {
            return Err(napi::Error::from_reason("duplicate recipient"));
        }
        if env.recipients.len() >= MAX_RECIPIENTS {
            return Err(napi::Error::from_reason("too many recipients"));
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
        let plain = Zeroizing::new(api(env.open(&api(self.encryption(&purpose))?))?);
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
    fn hkdf_vector_and_domain_separation() {
        // RFC 5869 test case 1 verifies the underlying extract/expand convention.
        let out = derive(
            &[0x0b; 22],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
        );
        assert_eq!(
            *out,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf
            ]
        );
        let master = MasterKey { bytes: [42; 32] };
        let a = master.child(b"alloy/master/ed25519/v1", "repo:1").unwrap();
        assert_eq!(
            *a,
            *master.child(b"alloy/master/ed25519/v1", "repo:1").unwrap()
        );
        assert_ne!(
            *a,
            *master.child(b"alloy/master/ed25519/v1", "repo:2").unwrap()
        );
        assert_ne!(
            *a,
            *master.child(b"alloy/master/x25519/v1", "repo:1").unwrap()
        );
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
