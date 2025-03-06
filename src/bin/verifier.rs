use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info};

use core::{
    api::{
        AttestationPayload, KeyInfo, KeyListResponse, PublicKey, RegisterKeyRequest,
        RegisterKeyResponse, VerifyRequest, VerifyResponse,
    },
    config::Config,
    key_store::SqliteKeyStore,
    logging,
    nonce_store::{NonceRequest, NonceResponse, NonceStore},
    verification::VerificationError,
};

#[derive(Clone)]
struct AppState {
    nonce_store: NonceStore,
    key_store: SqliteKeyStore,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::setup_default_logging()?;
    info!("Starting verifier service");

    let config = Config::from_env();

    if !std::path::Path::new(&config.db_path).exists() {
        std::fs::File::create(&config.db_path)?;
    }

    let db_url = format!("sqlite:{}", config.db_path);

    let key_store = SqliteKeyStore::new(&db_url).await?;
    let nonce_store = NonceStore::new(&db_url).await?;

    // Create app state
    let state = AppState {
        nonce_store,
        key_store,
    };

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build our application with routes
    let app = Router::new()
        .route("/api/nonce", post(generate_nonce))
        .route("/api/verify", post(verify_attestation))
        .route("/api/keys", post(register_key))
        .route("/api/keys", get(list_keys))
        .route("/api/keys/{key_id}", delete(deactivate_key))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Generate a new nonce for the holder
async fn generate_nonce(_: State<AppState>, _: Json<NonceRequest>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(NonceResponse {
            nonce: NonceStore::generate_nonce(),
        }),
    )
}

/// Verify an attestation from the holder
async fn verify_attestation(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> impl IntoResponse {
    match verify_jwt(&request.jwt, &state.key_store, &state.nonce_store).await {
        Ok(payload) => {
            info!(
                "Successfully verified attestation with nonce: {}",
                payload.nonce
            );
            (
                StatusCode::OK,
                Json(VerifyResponse {
                    verified: true,
                    message: format!("Successfully verified message: {}", payload.message),
                }),
            )
        }
        Err(err) => {
            error!("Verification failed: {}", err);
            (
                StatusCode::BAD_REQUEST,
                Json(VerifyResponse {
                    verified: false,
                    message: format!("Verification failed: {}", err),
                }),
            )
        }
    }
}

/// Verify a JWT token
async fn verify_jwt(
    token: &str,
    key_store: &SqliteKeyStore,
    nonce_store: &NonceStore,
) -> Result<AttestationPayload, VerificationError> {
    // Extract key ID from JWT header
    let key_id = extract_key_id_from_jwt(token)?;
    debug!("Extracted key ID from JWT: {}", key_id);

    // Get the public key for this key ID
    let public_key = match key_store.get_key(&key_id).await {
        Ok(Some(key)) => key,
        Ok(None) => {
            error!("Key not found: {}", key_id);
            return Err(VerificationError::KeyNotFound(key_id));
        }
        Err(e) => {
            error!("Database error when retrieving key: {}", e);
            return Err(VerificationError::RequestError(format!(
                "Database error: {}",
                e
            )));
        }
    };

    // Verify the JWT signature and decode the payload
    let payload = decode_and_verify_jwt(token, &public_key)?;
    debug!("JWT signature verified successfully");

    // Check if the nonce has been used before
    nonce_store.mark_used(&payload.nonce).await?;
    debug!("Nonce validated: {}", payload.nonce);

    Ok(payload)
}

/// Extract the key ID from a JWT token
fn extract_key_id_from_jwt(token: &str) -> Result<String, VerificationError> {
    // Split the JWT into parts
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(VerificationError::RequestError(
            "Invalid JWT format".to_string(),
        ));
    }

    // serde_json base64 decode
    let header_json = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| VerificationError::RequestError("Invalid JWT header encoding".to_string()))?;

    let header: serde_json::Value = serde_json::from_slice(&header_json)
        .map_err(|_| VerificationError::RequestError("Invalid JWT header JSON".to_string()))?;

    // Extract the key ID
    match header.get("kid") {
        Some(kid) => match kid.as_str() {
            Some(kid_str) => Ok(kid_str.to_string()),
            None => Err(VerificationError::RequestError(
                "Invalid kid format in JWT header".to_string(),
            )),
        },
        None => Err(VerificationError::RequestError(
            "Missing kid in JWT header".to_string(),
        )),
    }
}

/// Decode and verify a JWT token
fn decode_and_verify_jwt(
    token: &str,
    public_key_json: &str,
) -> Result<AttestationPayload, VerificationError> {
    // Parse the JWK from JSON
    let jwk = serde_json::from_str::<PublicKey>(public_key_json)
        .map_err(|e| VerificationError::RequestError(format!("Invalid JWK format: {}", e)))?;

    // Verify it's an RSA key
    let kty = jwk.kty.as_str();

    if kty != "RSA" {
        return Err(VerificationError::RequestError(format!(
            "Unsupported key type: {}",
            kty
        )));
    }

    // Extract the modulus (n) and exponent (e)
    let n = jwk.n.as_str();

    let e = jwk.e.as_str();

    // Create a decoding key from the RSA parameters
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(n, e)
        .map_err(|e| VerificationError::RequestError(format!("Invalid RSA components: {}", e)))?;

    // Set up validation parameters
    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);

    // Decode and verify the token
    let token_data = jsonwebtoken::decode::<AttestationPayload>(token, &decoding_key, &validation)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                VerificationError::InvalidSignature
            }
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                VerificationError::RequestError("Token has expired".to_string())
            }
            _ => VerificationError::JwtError(e),
        })?;

    Ok(token_data.claims)
}

/// Register a new key
async fn register_key(
    State(state): State<AppState>,
    Json(request): Json<RegisterKeyRequest>,
) -> impl IntoResponse {
    // Add the key to the store
    match state
        .key_store
        .add_key(
            &request.public_key.kid,
            &serde_json::to_string(&request.public_key).unwrap(),
        )
        .await
    {
        Ok(_) => {
            info!(
                "Registered new public key with ID: {}",
                request.public_key.kid
            );
            (
                StatusCode::OK,
                Json(RegisterKeyResponse {
                    success: true,
                    message: format!("Key registered successfully: {}", request.public_key.kid),
                }),
            )
        }
        Err(e) => {
            error!("Failed to register key: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RegisterKeyResponse {
                    success: false,
                    message: format!("Failed to register key: {}", e),
                }),
            )
        }
    }
}

/// List all active keys
async fn list_keys(State(state): State<AppState>) -> impl IntoResponse {
    match state.key_store.list_active_keys().await {
        Ok(keys) => {
            let key_infos = keys
                .into_iter()
                .map(|(key_id, _)| KeyInfo {
                    key_id,
                    description: None,
                })
                .collect();

            debug!("Listed active keys successfully");
            (StatusCode::OK, Json(KeyListResponse { keys: key_infos }))
        }
        Err(e) => {
            error!("Failed to list keys: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(KeyListResponse { keys: vec![] }),
            )
        }
    }
}

/// Deactivate a key
async fn deactivate_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> impl IntoResponse {
    match state.key_store.deactivate_key(&key_id).await {
        Ok(true) => {
            info!("Successfully deactivated key: {}", key_id);
            StatusCode::OK
        }
        Ok(false) => {
            error!("Key not found: {}", key_id);
            StatusCode::NOT_FOUND
        }
        Err(e) => {
            error!("Failed to deactivate key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
