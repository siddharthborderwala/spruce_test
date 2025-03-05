use std::env;
use std::path::PathBuf;

/// Configuration for the key verification system
#[derive(Debug, Clone)]
pub struct Config {
    /// URL of the verifier serice
    pub verifier_url: String,
    /// Directory where keys are stored
    pub keys_directory: PathBuf,
    /// Path to the SQLite database
    pub db_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            verifier_url: "http://127.0.0.1:3000".to_string(),
            keys_directory: PathBuf::from("keys"),
            db_path: "storage.db".to_string(),
        }
    }
}

impl Config {
    /// Create a configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            verifier_url: "http://127.0.0.1:3000".to_string(),
            keys_directory: PathBuf::from(
                env::var("KEYS_DIR").unwrap_or_else(|_| "keys".to_string()),
            ),
            db_path: env::var("DB_PATH").unwrap_or_else(|_| "storage.db".to_string()),
        }
    }
}
