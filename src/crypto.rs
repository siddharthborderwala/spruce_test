use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use rsa::{
    BigUint, RsaPrivateKey,
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use tracing::debug;

use crate::api::AttestationPayload;

/// Private key structure matching the one in holder.rs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrivateKey {
    pub kty: String,
    pub n: String,
    pub e: String,
    pub d: String,
    pub p: String,
    pub q: String,
    pub dp: String,
    pub dq: String,
    pub qi: String,
    pub kid: String,
}

fn jwk_to_pem(jwk: &PrivateKey) -> Result<String, Box<dyn Error>> {
    // Extract the RSA components from the JWK
    let n = decode_base64_component(&jwk.n)?;
    let e = decode_base64_component(&jwk.e)?;
    let d = decode_base64_component(&jwk.d)?;
    let p = decode_base64_component(&jwk.p)?;
    let q = decode_base64_component(&jwk.q)?;

    // Create RSA private key from components
    let private_key = RsaPrivateKey::from_components(
        BigUint::from_bytes_be(&n),
        BigUint::from_bytes_be(&e),
        BigUint::from_bytes_be(&d),
        vec![BigUint::from_bytes_be(&p), BigUint::from_bytes_be(&q)],
    )?;

    // Convert to PEM format
    let pem = private_key.to_pkcs1_pem(LineEnding::LF)?;

    Ok(pem.to_string())
}

fn decode_base64_component(value: &String) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(URL_SAFE_NO_PAD.decode(value)?)
}

/// Service for cryptographic operations
pub struct CryptoService;

impl CryptoService {
    /// Create an attestation payload with the given nonce and message
    pub fn create_attestation_payload(nonce: &str, message: &str) -> AttestationPayload {
        // Set expiration time to 5 minutes from now
        let expiration = Utc::now()
            .checked_add_signed(Duration::minutes(5))
            .expect("Valid timestamp")
            .timestamp();

        debug!(
            "Creating attestation payload with nonce: {}, message: {}, exp: {}",
            nonce, message, expiration
        );

        AttestationPayload {
            nonce: nonce.to_string(),
            message: message.to_string(),
            exp: expiration,
        }
    }

    /// Create a JWT header with the given key ID
    pub fn create_jwt_header(key_id: &str) -> Header {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(key_id.to_string());
        header.typ = Some("JWT".to_string());
        header
    }

    /// Overloaded version that accepts a JSON value for private key
    pub fn sign_payload_json(
        payload: &AttestationPayload,
        private_key: &PrivateKey,
        header: &Header,
    ) -> Result<String, Box<dyn Error>> {
        let key = private_key.clone();

        let pem = jwk_to_pem(&key)?;

        // Create an encoding key from the PEM
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())?;

        // Sign the payload
        let token = encode(header, payload, &encoding_key)?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_create_attestation_payload() {
        let nonce = "test-nonce";
        let message = "test-message";

        let payload = CryptoService::create_attestation_payload(nonce, message);

        assert_eq!(payload.nonce, nonce);
        assert_eq!(payload.message, message);
        assert!(payload.exp > Utc::now().timestamp());
    }

    #[test]
    fn test_create_jwt_header() {
        let key_id = "test-key-id";

        let header = CryptoService::create_jwt_header(key_id);

        assert_eq!(header.kid, Some(key_id.to_string()));
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
        assert_eq!(header.typ, Some("JWT".to_string()));
    }

    #[test]
    fn test_payload_expiration() {
        // Test that the expiration time is set correctly
        let nonce = "test-nonce";
        let message = "test-message";

        let payload = CryptoService::create_attestation_payload(nonce, message);

        // Expiration should be 5 minutes from now
        let now = Utc::now().timestamp();
        let five_minutes = 5 * 60; // 5 minutes in seconds

        // Allow for a small time difference due to test execution
        assert!(payload.exp >= now + five_minutes - 2);
        assert!(payload.exp <= now + five_minutes + 2);
    }

    #[test]
    fn test_header_algorithm() {
        // Test that the algorithm is set correctly
        let key_id = "test-key-id";
        let header = CryptoService::create_jwt_header(key_id);

        // The algorithm should be RS256 for RSA with SHA-256
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
    }
}
