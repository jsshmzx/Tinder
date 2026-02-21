CREATE TABLE IF NOT EXISTS tokens (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    belong_to TEXT NOT NULL,
    permission TEXT NOT NULL,
    assigner TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expired_at TIMESTAMP,
    current_status TEXT
);

CREATE INDEX IF NOT EXISTS idx_tokens_belong_to ON tokens (belong_to);
CREATE INDEX IF NOT EXISTS idx_tokens_expired_at ON tokens (expired_at);
