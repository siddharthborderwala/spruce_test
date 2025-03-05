use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use tracing::{error, info};
use ulid::Ulid;

use crate::verification::VerificationError;

/// SQLite-based nonce store to track used nonces
#[derive(Debug, Clone)]
pub struct NonceStore {
    pool: Arc<SqlitePool>,
}

impl NonceStore {
    pub async fn new(db_url: &str) -> Result<Self, sqlx::Error> {
        // Create a connection pool
        let pool = SqlitePool::connect(db_url).await?;

        // Initialize the database schema
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT PRIMARY KEY,
                used_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(&pool)
        .await?;

        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    pub fn generate_nonce() -> String {
        Ulid::new().to_string()
    }

    pub async fn mark_used(&self, nonce: &str) -> Result<(), VerificationError> {
        // First check if the nonce already exists
        let result = sqlx::query("SELECT nonce FROM used_nonces WHERE nonce = ?")
            .bind(nonce)
            .fetch_optional(&*self.pool)
            .await
            .map_err(|e| {
                error!("Database error when checking nonce: {}", e);
                VerificationError::RequestError(format!("Database error: {}", e))
            })?;

        if result.is_some() {
            return Err(VerificationError::NonceAlreadyUsed);
        }

        // Insert the nonce
        sqlx::query("INSERT INTO used_nonces (nonce) VALUES (?)")
            .bind(nonce)
            .execute(&*self.pool)
            .await
            .map_err(|e| {
                error!("Database error when storing nonce: {}", e);
                VerificationError::RequestError(format!("Database error: {}", e))
            })?;

        info!("Marked nonce as used: {}", nonce);
        Ok(())
    }

    pub async fn cleanup_old_nonces(&self, days: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM used_nonces WHERE used_at < datetime('now', ?)")
            .bind(format!("-{} days", days))
            .execute(&*self.pool)
            .await?;

        let rows_affected = result.rows_affected();
        info!("Cleaned up {} old nonces", rows_affected);

        Ok(rows_affected)
    }
}

/// Request to generate a nonce
#[derive(Debug, Serialize, Deserialize)]
pub struct NonceRequest {}

/// Response containing a generated nonce
#[derive(Debug, Serialize, Deserialize)]
pub struct NonceResponse {
    pub nonce: String,
}
