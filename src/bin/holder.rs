use core::api::{NonceResponse, VerifyResponse};
use core::config::Config;
use core::crypto::{CryptoService, PrivateKey};
use core::logging;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use tracing::{debug, error, info};

const DEFAULT_MESSAGE: &str = "Hello from Siddharth!";

#[derive(Debug, Serialize, Deserialize)]
struct PrivateKeySet {
    keys: Vec<PrivateKey>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    logging::setup_default_logging()?;
    info!("Starting holder script");

    // Load configuration
    let config = Config::from_env();

    // Create key manager
    let private_jwk = Path::new(&config.keys_directory).join("private.jwk");

    // read the file
    let private_key_set = File::open(private_jwk)?;

    // read the file into json with keys array
    let private_key_set = serde_json::from_reader::<_, PrivateKeySet>(private_key_set)?;

    let keys = private_key_set.keys;

    let (key_id, private_key) = {
        if keys.is_empty() {
            error!("No private keys found");
            println!("Please run the key generation tool first:");
            println!("  cargo run --bin keygen");
            return Err("No private keys found".into());
        }

        // If there's only one key, use it automatically
        if keys.len() == 1 {
            let key_id = keys[0].kid.clone();
            debug!("Found single private key: {}", key_id);
            (key_id, keys[0].clone())
        } else {
            // Otherwise, let the user choose
            println!("Multiple private keys found. Please select one:");

            for (i, key) in keys.iter().enumerate() {
                println!("{}. {}", i + 1, key.kid);
            }

            print!("Enter selection (1-{}): ", keys.len());
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            let selection = input
                .trim()
                .parse::<usize>()
                .map_err(|_| "Invalid selection")?;

            if selection < 1 || selection > keys.len() {
                return Err(format!("Invalid selection: {}", selection).into());
            }

            let index = selection - 1;
            let selected_key_id = keys[index].kid.clone();

            debug!("Selected key: {}", selected_key_id);
            (selected_key_id, keys[index].clone())
        }
    };

    info!("Using key ID: {}", key_id);

    let nonce_url = "http://127.0.0.1:3000/api/nonce";
    let client = reqwest::Client::new();

    // Step 1: Get a nonce from the verifier
    debug!("Requesting nonce from verifier");
    let nonce = match client.post(nonce_url).json(&json!({})).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                let error_msg = format!("Failed to get nonce: HTTP {}", response.status());
                error!("{}", error_msg);
                return Err(error_msg.into());
            }

            // Debug the response
            let response_text = response.text().await?;
            debug!("Received response: {}", response_text);

            // Parse the response
            match serde_json::from_str::<NonceResponse>(&response_text) {
                Ok(nonce_response) => nonce_response.nonce,
                Err(e) => {
                    let error_msg = format!(
                        "Failed to parse nonce response: {}, Response: {}",
                        e, response_text
                    );
                    error!("{}", error_msg);
                    return Err(error_msg.into());
                }
            }
        }
        Err(e) => {
            error!("Failed to get nonce: {}", e);
            return Err(e.into());
        }
    };

    debug!("Received nonce: {}", nonce);

    // Step 2: Prompt user for a custom message or use default
    let message = prompt_for_message()?;
    debug!("Creating attestation with message: '{}'", message);

    // Create attestation payload
    let payload = CryptoService::create_attestation_payload(&nonce, &message);

    // Create JWT header with key ID
    let header = CryptoService::create_jwt_header(&key_id);
    debug!("Added key ID '{}' to JWT header", key_id);

    // Sign the payload with the private key
    let jwt = match CryptoService::sign_payload(&payload, &private_key, &header) {
        Ok(jwt) => {
            debug!("Created JWT: {}", jwt);
            debug!("Successfully signed the payload");
            jwt
        }
        Err(e) => {
            error!("Failed to sign payload: {}", e);
            return Err(e.into());
        }
    };

    let verify_url = "http://127.0.0.1:3000/api/verify";

    // Step 3: Send the signed payload to the verifier
    debug!("Sending attestation to verifier for verification");
    match client
        .post(verify_url)
        .json(&json!({
            "jwt": jwt
        }))
        .send()
        .await
    {
        Ok(response) => {
            if !response.status().is_success() {
                let error_msg = format!("Verification failed: HTTP {}", response.status());
                error!("{}", error_msg);
                println!("❌ {}", error_msg);
                return Err(error_msg.into());
            }

            // Debug the response
            let response_text = response.text().await?;
            debug!("Received verification response: {}", response_text);

            // Parse the response
            match serde_json::from_str::<VerifyResponse>(&response_text) {
                Ok(verify_response) => {
                    if verify_response.verified {
                        info!("✅ Verification successful: {}", verify_response.message);
                        println!(
                            "✅ Successfully verified message: {}",
                            verify_response.message
                        );
                    } else {
                        error!("❌ Verification failed: {}", verify_response.message);
                        println!("❌ Verification failed: {}", verify_response.message);
                    }
                }
                Err(e) => {
                    let error_msg = format!(
                        "Failed to parse verification response: {}, Response: {}",
                        e, response_text
                    );
                    error!("{}", error_msg);
                    println!("❌ {}", error_msg);
                    return Err(error_msg.into());
                }
            }
        }
        Err(e) => {
            error!("Failed to verify attestation: {}", e);
            println!("❌ Verification failed: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

/// Prompt the user for a custom message or use the default
fn prompt_for_message() -> Result<String, Box<dyn Error>> {
    println!("Enter a custom message or press Enter to use the default:");
    print!("> ");
    io::stdout().flush()?;

    let mut message = String::new();
    io::stdin().read_line(&mut message)?;
    let message = message.trim();

    if message.is_empty() {
        debug!("Using default message: \"{}\"", DEFAULT_MESSAGE);
        Ok(DEFAULT_MESSAGE.to_string())
    } else {
        debug!("Using custom message: \"{}\"", message);
        Ok(message.to_string())
    }
}
