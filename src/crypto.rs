use chrono::{Duration, Utc};
use jsonwebkey::{Key, PublicExponent, RsaPrivate, RsaPublic};
use jsonwebtoken::{EncodingKey, Header, encode};
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

        // TODO: Implement this
        let key = Key::RSA {
            public: RsaPublic {
                n: key.n.into(),
                e: PublicExponent,
            },
            private: Some(RsaPrivate {
                d: key.d.into(),
                p: Some(key.p.as_bytes().into()),
                q: Some(key.q.as_bytes().into()),
                dp: Some(key.dp.as_bytes().into()),
                dq: Some(key.dq.as_bytes().into()),
                qi: Some(key.qi.as_bytes().into()),
            }),
        };

        // Create an encoding key from the PEM
        let encoding_key = EncodingKey::from_rsa_pem(key.to_pem().as_bytes())?;

        // Sign the payload
        let token = encode(header, payload, &encoding_key)?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
