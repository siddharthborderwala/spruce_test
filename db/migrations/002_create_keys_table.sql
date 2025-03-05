-- Migration to create the keys table for storing public keys
CREATE TABLE IF NOT EXISTS keys (
    key_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

-- Index for faster lookups of active keys
CREATE INDEX IF NOT EXISTS idx_keys_active ON keys(active);
