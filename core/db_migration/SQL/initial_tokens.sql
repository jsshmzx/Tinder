CREATE TABLE IF NOT EXISTS tokens (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    belong_to TEXT,
    permission TEXT,
    assigner TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expired_at TIMESTAMP,
    status TEXT
);
