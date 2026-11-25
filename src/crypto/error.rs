//! Shared errors for the repository cryptography protocols.

use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    #[error("purpose must contain between 1 and 4096 UTF-8 bytes")]
    InvalidPurpose,
    #[error("unsupported identity-key version")]
    UnsupportedVersion,
    #[error("random generator failed")]
    RandomFailure,
    #[error("context must contain between 1 and 4096 UTF-8 bytes")]
    InvalidContext,
    #[error("envelope too large")]
    EnvelopeTooLarge,
    #[error("invalid envelope encoding")]
    InvalidEnvelopeEncoding,
    #[error("unsupported envelope protocol")]
    UnsupportedEnvelopeProtocol,
    #[error("context mismatch")]
    ContextMismatch,
    #[error("invalid envelope structure")]
    InvalidEnvelopeStructure,
    #[error("plaintext too large")]
    PlaintextTooLarge,
    #[error("invalid recipient count")]
    InvalidRecipientCount,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("duplicate recipient")]
    DuplicateRecipient,
    #[error("too many recipients")]
    TooManyRecipients,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("serialization failed")]
    SerializationFailed,
    #[error("invalid repository identifier")]
    InvalidRepositoryId,
    #[error("invalid manifest structure")]
    InvalidManifestStructure,
    #[error("manifest too large")]
    ManifestTooLarge,
    #[error("invalid manifest encoding")]
    InvalidManifestEncoding,
    #[error("unsupported manifest protocol")]
    UnsupportedManifestProtocol,
    #[error("manifest does not describe this envelope")]
    EnvelopeMismatch,
    #[error("repository mismatch")]
    RepositoryMismatch,
    #[error("manifest generation is stale")]
    StaleGeneration,
    #[error("manifest signer is not trusted")]
    UntrustedSigner,
    #[error("invalid manifest signature")]
    InvalidSignature,
}

pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

impl From<CryptoError> for napi::Error {
    fn from(error: CryptoError) -> Self {
        Self::from_reason(error.to_string())
    }
}
