CREATE TABLE IF NOT EXISTS vote (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    vote_type TEXT,
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    committed_by TEXT,
    content TEXT
);
