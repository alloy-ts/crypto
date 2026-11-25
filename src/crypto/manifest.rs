//! Signed repository authorization manifests.

use super::{
    core::{IdentityKeys, MasterKey},
    envelope::{envelope_recipient_ids, recipient_id},
    error::{CryptoError, CryptoResult},
};
use ed25519_dalek::{Signature, VerifyingKey};
use napi::bindgen_prelude::{BigInt, Buffer};
use napi_derive::napi;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as X25519PublicKey;

const MANIFEST_VERSION: u32 = 1;
const MAX_RECIPIENTS: usize = 256;
const MAX_TRUSTED_SIGNERS: usize = 256;
const MAX_JSON: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryManifest {
    version: u32,
    repository_id: [u8; 32],
    generation: u64,
    recipients: Vec<[u8; 32]>,
    envelope_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    manifest: RepositoryManifest,
    signer: [u8; 32],
    signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustPolicy {
    repository_id: [u8; 32],
    minimum_generation: u64,
    trusted_signers: Vec<[u8; 32]>,
}

fn transcript(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn validate_repository_id(repository_id: &[u8; 32]) -> CryptoResult<()> {
    if repository_id.iter().all(|byte| *byte == 0) {
        return Err(CryptoError::InvalidRepositoryId);
    }
    Ok(())
}

fn canonical_recipients(mut recipients: Vec<[u8; 32]>) -> CryptoResult<Vec<[u8; 32]>> {
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(CryptoError::InvalidRecipientCount);
    }
    if recipients
        .iter()
        .any(|recipient| recipient.iter().all(|byte| *byte == 0))
    {
        return Err(CryptoError::InvalidPublicKey);
    }
    recipients.sort_unstable();
    if recipients.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CryptoError::DuplicateRecipient);
    }
    Ok(recipients)
}

fn recipient_ids(recipients: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut ids = recipients
        .iter()
        .map(|key| recipient_id(&X25519PublicKey::from(*key)))
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

impl RepositoryManifest {
    pub fn new(
        repository_id: [u8; 32],
        generation: u64,
        recipients: Vec<[u8; 32]>,
        envelope: &str,
    ) -> CryptoResult<Self> {
        validate_repository_id(&repository_id)?;
        let recipients = canonical_recipients(recipients)?;
        let manifest = Self {
            version: MANIFEST_VERSION,
            repository_id,
            generation,
            recipients,
            envelope_hash: Sha256::digest(envelope.as_bytes()).into(),
        };
        manifest.verify_envelope(envelope)?;
        Ok(manifest)
    }

    pub fn repository_id(&self) -> [u8; 32] {
        self.repository_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn recipients(&self) -> &[[u8; 32]] {
        &self.recipients
    }

    pub fn envelope_hash(&self) -> [u8; 32] {
        self.envelope_hash
    }

    pub fn verify_envelope(&self, envelope: &str) -> CryptoResult<()> {
        self.validate()?;
        let envelope_hash: [u8; 32] = Sha256::digest(envelope.as_bytes()).into();
        if self.envelope_hash != envelope_hash {
            return Err(CryptoError::EnvelopeMismatch);
        }
        if recipient_ids(&self.recipients) != envelope_recipient_ids(envelope)? {
            return Err(CryptoError::EnvelopeMismatch);
        }
        Ok(())
    }

    fn validate(&self) -> CryptoResult<()> {
        if self.version != MANIFEST_VERSION {
            return Err(CryptoError::UnsupportedManifestProtocol);
        }
        validate_repository_id(&self.repository_id)?;
        if canonical_recipients(self.recipients.clone())? != self.recipients {
            return Err(CryptoError::InvalidManifestStructure);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut recipient_bytes = Vec::with_capacity(self.recipients.len() * 32 + 8);
        recipient_bytes.extend_from_slice(&(self.recipients.len() as u64).to_be_bytes());
        for recipient in &self.recipients {
            recipient_bytes.extend_from_slice(recipient);
        }
        transcript(&[
            b"alloy/repository-manifest/v1",
            &self.version.to_be_bytes(),
            &self.repository_id,
            &self.generation.to_be_bytes(),
            &recipient_bytes,
            &self.envelope_hash,
        ])
    }
}

impl SignedManifest {
    pub fn manifest(&self) -> &RepositoryManifest {
        &self.manifest
    }

    pub fn signer(&self) -> [u8; 32] {
        self.signer
    }

    pub fn signature(&self) -> [u8; 64] {
        self.signature
            .as_slice()
            .try_into()
            .expect("validated manifest signature length")
    }

    pub fn to_json(&self) -> CryptoResult<String> {
        serde_json::to_string(self).map_err(|_| CryptoError::SerializationFailed)
    }

    pub fn from_json(json: &str) -> CryptoResult<Self> {
        if json.len() > MAX_JSON {
            return Err(CryptoError::ManifestTooLarge);
        }
        let signed: Self =
            serde_json::from_str(json).map_err(|_| CryptoError::InvalidManifestEncoding)?;
        signed.validate()?;
        Ok(signed)
    }

    fn signing_message(&self) -> Vec<u8> {
        let manifest = self.manifest.canonical_bytes();
        transcript(&[
            b"alloy/repository-manifest-signature/v1",
            &manifest,
            &self.signer,
        ])
    }

    fn validate(&self) -> CryptoResult<()> {
        self.manifest.validate()?;
        if self.signature.len() != 64 || VerifyingKey::from_bytes(&self.signer).is_err() {
            return Err(CryptoError::InvalidManifestStructure);
        }
        Ok(())
    }
}

impl TrustPolicy {
    pub fn new(
        repository_id: [u8; 32],
        minimum_generation: u64,
        mut trusted_signers: Vec<[u8; 32]>,
    ) -> CryptoResult<Self> {
        validate_repository_id(&repository_id)?;
        if trusted_signers.is_empty() || trusted_signers.len() > MAX_TRUSTED_SIGNERS {
            return Err(CryptoError::InvalidManifestStructure);
        }
        if trusted_signers
            .iter()
            .any(|key| VerifyingKey::from_bytes(key).is_err())
        {
            return Err(CryptoError::InvalidPublicKey);
        }
        trusted_signers.sort_unstable();
        if trusted_signers.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CryptoError::InvalidManifestStructure);
        }
        Ok(Self {
            repository_id,
            minimum_generation,
            trusted_signers,
        })
    }
}

pub fn sign_manifest(manifest: &RepositoryManifest, signer: &IdentityKeys) -> SignedManifest {
    let mut signed = SignedManifest {
        manifest: manifest.clone(),
        signer: signer.signing_public_key(),
        signature: vec![],
    };
    signed.signature = signer.sign(&signed.signing_message()).to_vec();
    signed
}

pub fn verify_manifest(
    signed: &SignedManifest,
    policy: &TrustPolicy,
    envelope: &str,
) -> CryptoResult<RepositoryManifest> {
    signed.validate()?;
    if signed.manifest.repository_id != policy.repository_id {
        return Err(CryptoError::RepositoryMismatch);
    }
    if signed.manifest.generation < policy.minimum_generation {
        return Err(CryptoError::StaleGeneration);
    }
    if policy
        .trusted_signers
        .binary_search(&signed.signer)
        .is_err()
    {
        return Err(CryptoError::UntrustedSigner);
    }
    signed.manifest.verify_envelope(envelope)?;
    VerifyingKey::from_bytes(&signed.signer)
        .map_err(|_| CryptoError::InvalidManifestStructure)?
        .verify_strict(
            &signed.signing_message(),
            &Signature::from_slice(&signed.signature)
                .map_err(|_| CryptoError::InvalidManifestStructure)?,
        )
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(signed.manifest.clone())
}

fn buffer32(buffer: &Buffer, error: CryptoError) -> napi::Result<[u8; 32]> {
    buffer.as_ref().try_into().map_err(|_| error.into())
}

fn buffers32(buffers: Vec<Buffer>, error: CryptoError) -> napi::Result<Vec<[u8; 32]>> {
    buffers
        .iter()
        .map(|buffer| buffer32(buffer, error))
        .collect()
}

fn u64_from_bigint(value: BigInt) -> napi::Result<u64> {
    let (negative, value, lossless) = value.get_u64();
    if negative || !lossless {
        return Err(napi::Error::from_reason(
            "generation must be an unsigned 64-bit bigint",
        ));
    }
    Ok(value)
}

#[napi]
impl MasterKey {
    #[napi]
    pub fn sign_manifest(
        &self,
        purpose: String,
        repository_id: Buffer,
        generation: BigInt,
        recipients: Vec<Buffer>,
        envelope: String,
    ) -> napi::Result<String> {
        let identity = self
            .derive_identity(&purpose, 1)
            .map_err(napi::Error::from)?;
        let manifest = RepositoryManifest::new(
            buffer32(&repository_id, CryptoError::InvalidRepositoryId)?,
            u64_from_bigint(generation)?,
            buffers32(recipients, CryptoError::InvalidPublicKey)?,
            &envelope,
        )?;
        sign_manifest(&manifest, &identity)
            .to_json()
            .map_err(Into::into)
    }
}

#[napi(js_name = "verifyManifest")]
pub fn verify_manifest_node(
    signed_manifest: String,
    expected_repository_id: Buffer,
    minimum_generation: BigInt,
    trusted_signers: Vec<Buffer>,
    envelope: String,
) -> napi::Result<bool> {
    let signed = SignedManifest::from_json(&signed_manifest)?;
    let policy = TrustPolicy::new(
        buffer32(&expected_repository_id, CryptoError::InvalidRepositoryId)?,
        u64_from_bigint(minimum_generation)?,
        buffers32(trusted_signers, CryptoError::InvalidPublicKey)?,
    )?;
    verify_manifest(&signed, &policy, &envelope)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::envelope::seal_envelope;

    fn fixture() -> (MasterKey, MasterKey, String, Vec<[u8; 32]>) {
        let admin = MasterKey::from_bytes([7; 32]);
        let outsider = MasterKey::from_bytes([8; 32]);
        let recipient = admin.derive_identity("recipient:1", 1).unwrap();
        let recipients = vec![recipient.encryption_public_key()];
        let envelope = seal_envelope(
            "repo:1/object:1".into(),
            Buffer::from(b"secret".to_vec()),
            recipients
                .iter()
                .map(|key| Buffer::from(key.to_vec()))
                .collect(),
        )
        .unwrap();
        (admin, outsider, envelope, recipients)
    }

    #[test]
    fn trusted_manifest_roundtrip_binds_envelope_and_recipients() {
        let (admin, _, envelope, recipients) = fixture();
        let repository_id = [9; 32];
        let manifest = RepositoryManifest::new(repository_id, 4, recipients, &envelope).unwrap();
        let signer = admin.derive_identity("administrator:1", 1).unwrap();
        let signed = sign_manifest(&manifest, &signer);
        let decoded = SignedManifest::from_json(&signed.to_json().unwrap()).unwrap();
        let policy = TrustPolicy::new(repository_id, 4, vec![signer.signing_public_key()]).unwrap();

        assert_eq!(
            verify_manifest(&decoded, &policy, &envelope).unwrap(),
            manifest
        );
        assert_eq!(signed, sign_manifest(&manifest, &signer));
    }

    #[test]
    fn manifest_signature_golden_vector() {
        let manifest = RepositoryManifest {
            version: MANIFEST_VERSION,
            repository_id: [1; 32],
            generation: 7,
            recipients: vec![[2; 32], [3; 32]],
            envelope_hash: [4; 32],
        };
        let signer = MasterKey::from_bytes([5; 32])
            .derive_identity("administrator:golden", 1)
            .unwrap();
        let signed = sign_manifest(&manifest, &signer);
        assert_eq!(
            signed.signer,
            [
                0x69, 0x7a, 0xa7, 0xdd, 0x48, 0xdd, 0xab, 0xab, 0xb2, 0x76, 0x70, 0xff, 0xf4, 0x51,
                0x0f, 0x00, 0xc3, 0xab, 0xef, 0x49, 0x78, 0xb7, 0xf6, 0xf7, 0x61, 0x57, 0xe7, 0xeb,
                0xaa, 0xa9, 0x0e, 0x54,
            ]
        );
        assert_eq!(
            signed.signature,
            [
                0x95, 0x79, 0x9c, 0x3d, 0xc2, 0xfe, 0xff, 0x1e, 0xd8, 0x00, 0xf0, 0x2c, 0xac, 0x18,
                0x3b, 0xf6, 0x96, 0x19, 0x55, 0x8b, 0x2b, 0x23, 0xcd, 0x30, 0x07, 0x65, 0x96, 0x86,
                0x60, 0x58, 0x94, 0xf4, 0x62, 0xd5, 0x99, 0x74, 0x85, 0xa2, 0xec, 0xdc, 0x08, 0xb7,
                0x18, 0x0e, 0xfb, 0x2c, 0xde, 0x14, 0xcf, 0x6d, 0x92, 0xf7, 0x7e, 0xc0, 0x0d, 0x23,
                0x11, 0x70, 0xf3, 0x46, 0x81, 0xcf, 0x11, 0x01,
            ]
        );
    }

    #[test]
    fn rejects_untrusted_stale_tampered_and_mismatched_manifests() {
        let (admin, outsider, envelope, recipients) = fixture();
        let repository_id = [9; 32];
        let manifest =
            RepositoryManifest::new(repository_id, 4, recipients.clone(), &envelope).unwrap();
        let signer = admin.derive_identity("administrator:1", 1).unwrap();
        let outsider = outsider.derive_identity("administrator:1", 1).unwrap();
        let signed = sign_manifest(&manifest, &signer);

        let untrusted =
            TrustPolicy::new(repository_id, 4, vec![outsider.signing_public_key()]).unwrap();
        assert_eq!(
            verify_manifest(&signed, &untrusted, &envelope).unwrap_err(),
            CryptoError::UntrustedSigner
        );

        let stale = TrustPolicy::new(repository_id, 5, vec![signer.signing_public_key()]).unwrap();
        assert_eq!(
            verify_manifest(&signed, &stale, &envelope).unwrap_err(),
            CryptoError::StaleGeneration
        );

        let policy = TrustPolicy::new(repository_id, 4, vec![signer.signing_public_key()]).unwrap();
        assert_eq!(
            verify_manifest(&signed, &policy, &(envelope.clone() + " ")).unwrap_err(),
            CryptoError::EnvelopeMismatch
        );

        let mut tampered = signed.clone();
        tampered.signature[0] ^= 1;
        assert_eq!(
            verify_manifest(&tampered, &policy, &envelope).unwrap_err(),
            CryptoError::InvalidSignature
        );

        let extra = admin
            .derive_identity("recipient:2", 1)
            .unwrap()
            .encryption_public_key();
        assert_eq!(
            RepositoryManifest::new(repository_id, 4, vec![recipients[0], extra], &envelope)
                .unwrap_err(),
            CryptoError::EnvelopeMismatch
        );
    }

    #[test]
    fn rejects_noncanonical_and_malformed_manifest_input() {
        let (admin, _, envelope, recipients) = fixture();
        let repository_id = [9; 32];
        assert_eq!(
            RepositoryManifest::new([0; 32], 1, recipients.clone(), &envelope).unwrap_err(),
            CryptoError::InvalidRepositoryId
        );
        assert_eq!(
            RepositoryManifest::new(
                repository_id,
                1,
                vec![recipients[0], recipients[0]],
                &envelope,
            )
            .unwrap_err(),
            CryptoError::DuplicateRecipient
        );

        let signer = admin.derive_identity("administrator:1", 1).unwrap();
        let manifest = RepositoryManifest::new(repository_id, 1, recipients, &envelope).unwrap();
        let encoded = sign_manifest(&manifest, &signer).to_json().unwrap();
        assert_eq!(
            SignedManifest::from_json(&encoded.replacen('{', "{\"extra\":0,", 1)).unwrap_err(),
            CryptoError::InvalidManifestEncoding
        );
    }
}
