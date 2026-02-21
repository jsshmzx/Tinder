CREATE TABLE IF NOT EXISTS tags (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tag_name TEXT NOT NULL,
    created_by TEXT,
    current_status TEXT
);
