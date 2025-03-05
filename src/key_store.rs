use sqlx::{Row, sqlite::SqlitePool};
use std::sync::Arc;
use tracing::{error, info};

/// SQLite-based key store for managing public keys
#[derive(Clone)]
pub struct SqliteKeyStore {
    pool: Arc<SqlitePool>,
}

impl SqliteKeyStore {
    pub async fn new(db_url: &str) -> Result<Self, sqlx::Error> {
        // Create a connection pool
        let pool = SqlitePool::connect(db_url).await?;

        // Initialize the database schema
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS public_keys (
                key_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                description TEXT,
                is_active BOOLEAN NOT NULL DEFAULT TRUE
            )",
        )
        .execute(&pool)
        .await?;

        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    pub async fn add_key(&self, key_id: &str, public_key: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO public_keys (key_id, public_key, description) 
             VALUES (?, ?, ?) 
             ON CONFLICT(key_id) DO UPDATE SET 
                public_key = excluded.public_key,
                description = excluded.description,
                is_active = TRUE",
        )
        .bind(key_id)
        .bind(public_key)
        .execute(&*self.pool)
        .await?;

        info!("Added/updated public key with ID: {}", key_id);
        Ok(())
    }

    pub async fn get_key(&self, key_id: &str) -> Result<Option<String>, sqlx::Error> {
        let result = sqlx::query(
            "SELECT public_key FROM public_keys 
             WHERE key_id = ? AND is_active = TRUE",
        )
        .bind(key_id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(result.map(|row| row.get(0)))
    }

    pub async fn deactivate_key(&self, key_id: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE public_keys SET is_active = FALSE 
             WHERE key_id = ?",
        )
        .bind(key_id)
        .execute(&*self.pool)
        .await?;

        let rows_affected = result.rows_affected();
        if rows_affected > 0 {
            info!("Deactivated key with ID: {}", key_id);
        } else {
            error!("Failed to deactivate key with ID: {} (not found)", key_id);
        }

        Ok(rows_affected > 0)
    }

    pub async fn list_active_keys(&self) -> Result<Vec<(String, String)>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT key_id, public_key FROM public_keys 
             WHERE is_active = TRUE 
             ORDER BY created_at DESC",
        )
        .fetch_all(&*self.pool)
        .await?;

        let keys = rows
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect();

        Ok(keys)
    }
}
