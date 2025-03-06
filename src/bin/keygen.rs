use josekit::jwk::Jwk;
use serde_json::{Value, json};
use spruce_test::logging;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::setup_default_logging()?;
    info!("Starting keygen service");

    let pbuf = PathBuf::from("./keys");

    // check if the directory exists
    if !pbuf.exists() {
        info!("Creating directory: {}", pbuf.display());
        fs::create_dir_all(&pbuf)?;
    }

    info!("Generating RSA keypair with {} bits...", 2048);

    print!("Enter unique ID for key: ");
    std::io::stdout().flush()?;
    let mut key_id = String::new();
    std::io::stdin().read_line(&mut key_id)?;
    let key_id = key_id.trim();

    if key_id.is_empty() {
        error!("Key ID cannot be empty");
        return Err("Key ID cannot be empty".into());
    }

    // check if the key id is present in private.jwk
    let key_exists = if pbuf.join("private.jwk").exists() {
        let mut file = File::open(&pbuf.join("private.jwk"))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let keys: Value = serde_json::from_str(&contents)?;
        let keys_array = keys.get("keys").and_then(|v| v.as_array());

        if let Some(keys) = keys_array {
            keys.iter()
                .any(|key| key.get("kid").and_then(|kid| kid.as_str()) == Some(key_id))
        } else {
            false
        }
    } else {
        false
    };

    if key_exists {
        error!("Key ID already in use");
        return Err("Key ID already in use".into());
    }

    // Generate RSA key pair using josekit
    let mut jwk = Jwk::generate_rsa_key(2048)?;
    jwk.set_key_id(key_id);

    // Extract public key
    let public_jwk = jwk.to_public_key()?;

    let mut public_map = serde_json::Map::new();
    public_map.insert("kty".to_string(), json!(public_jwk.key_type()));
    public_map.insert("kid".to_string(), json!(key_id));

    if let Some(n) = public_jwk.parameter("n") {
        public_map.insert("n".to_string(), n.clone());
    }
    if let Some(e) = public_jwk.parameter("e") {
        public_map.insert("e".to_string(), e.clone());
    }

    let public_jwk_json = json!(public_map);

    // Save public key as JSON
    let public_json = {
        // Check if public.jwk exists and read existing keys
        let public_jwk_set = if pbuf.join("public.jwk").exists() {
            let mut file = File::open(&pbuf.join("public.jwk"))?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;

            let mut existing_set: Value = serde_json::from_str(&contents)?;

            // Add the new key to the existing set
            if let Some(keys) = existing_set.get_mut("keys").and_then(|k| k.as_array_mut()) {
                keys.push(public_jwk_json.clone());
                existing_set
            } else {
                json!({
                    "keys": [public_jwk_json]
                })
            }
        } else {
            json!({
                "keys": [public_jwk_json]
            })
        };

        serde_json::to_string_pretty(&public_jwk_set)?
    };

    let mut public_file = File::create(&pbuf.join("public.jwk"))?;
    public_file.write_all(public_json.as_bytes())?;
    info!("Public key saved to: {}", pbuf.join("public.jwk").display());

    // Save private key as JSON
    let mut private_map = serde_json::Map::new();

    // Add all parameters from the JWK
    for key in &["kty", "n", "e", "d", "p", "q", "dp", "dq", "qi"] {
        if let Some(value) = jwk.parameter(key) {
            private_map.insert(key.to_string(), value.clone());
        }
    }
    private_map.insert("kid".to_string(), json!(key_id));

    let private_jwk_json = json!(private_map);

    // Check if private.jwk exists and read existing keys
    let private_jwk_set = if pbuf.join("private.jwk").exists() {
        let mut file = File::open(&pbuf.join("private.jwk"))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let mut existing_set: Value = serde_json::from_str(&contents)?;

        // Add the new key to the existing set
        if let Some(keys) = existing_set.get_mut("keys").and_then(|k| k.as_array_mut()) {
            keys.push(private_jwk_json);
            existing_set
        } else {
            json!({
                "keys": [private_jwk_json]
            })
        }
    } else {
        json!({
            "keys": [private_jwk_json]
        })
    };

    let private_json = serde_json::to_string_pretty(&private_jwk_set)?;
    let mut private_file = File::create(&pbuf.join("private.jwk"))?;
    private_file.write_all(private_json.as_bytes())?;

    info!(
        "Private key saved to: {}",
        pbuf.join("private.jwk").display()
    );

    let keygen_url = "http://127.0.0.1:3000/api/keys";
    let client = reqwest::Client::new();

    match client
        .post(keygen_url)
        .json(&json!({
            "public_key": public_jwk_json
        }))
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                info!("Key registered with verifier web service");
            } else {
                error!(
                    "Failed to register key with verifier web service: {}",
                    response.status()
                );
            }
        }
        Err(e) => {
            error!("Verifier web service request failed: {}", e);
        }
    }

    Ok(())
}
