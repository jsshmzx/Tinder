CREATE TABLE IF NOT EXISTS songs (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    singer TEXT,
    platform TEXT,
    committed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT,
    vote INTEGER DEFAULT 0,
    recommend_by TEXT,
    recommend_words TEXT,
    reason TEXT
);
