CREATE TABLE IF NOT EXISTS illegal_requests (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    "user" TEXT NOT NULL DEFAULT 'unknown',
    happened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    type TEXT NOT NULL,
    path TEXT NOT NULL,
    ip TEXT NOT NULL,
    ua TEXT
);

CREATE INDEX IF NOT EXISTS idx_illegal_requests_ip ON illegal_requests (ip);
CREATE INDEX IF NOT EXISTS idx_illegal_requests_happened_at ON illegal_requests (happened_at);
