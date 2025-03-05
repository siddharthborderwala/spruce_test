use thiserror::Error;

/// Error types for the key verification system
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Nonce already used")]
    NonceAlreadyUsed,
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Request error: {0}")]
    RequestError(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
}
