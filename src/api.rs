use serde::{Deserialize, Serialize};

/// Payload to be signed by the holder
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationPayload {
    pub nonce: String,
    pub message: String,
    pub exp: i64,
}

/// Request to verify an attestation
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub jwt: String,
}

/// Response from verification
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub message: String,
}

/// Request to register a key with the verifier
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterKeyRequest {
    /// Public key in JSON format
    pub public_key: PublicKey,
}

/// Response from key registration
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterKeyResponse {
    /// Whether the registration was successful
    pub success: bool,
    /// Message from the server
    pub message: String,
}

/// Request to generate a nonce
#[derive(Debug, Serialize, Deserialize)]
pub struct NonceRequest {}

/// Response containing a generated nonce
#[derive(Debug, Serialize, Deserialize)]
pub struct NonceResponse {
    /// The generated nonce
    pub nonce: String,
}

/// Response for listing keys
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyListResponse {
    pub keys: Vec<KeyInfo>,
}

/// Information about a key
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyInfo {
    pub key_id: String,
    pub description: Option<String>,
}

/// Public key in JSON format
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub kty: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}
