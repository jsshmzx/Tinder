CREATE TABLE IF NOT EXISTS song_arrangements (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    week_number INTEGER NOT NULL,
    content TEXT,
    created_by TEXT,
    likes INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
