-- Migration to create the used_nonces table for tracking used nonces
CREATE TABLE IF NOT EXISTS used_nonces (
    nonce TEXT PRIMARY KEY,
    used_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for faster lookups by timestamp (useful for cleanup operations)
CREATE INDEX IF NOT EXISTS idx_nonces_used_at ON used_nonces(used_at); 
