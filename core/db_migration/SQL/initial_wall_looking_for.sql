CREATE TABLE IF NOT EXISTS wall_looking_for (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    current_status TEXT,
    real_status TEXT,
    seeker TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    looking_for_type TEXT,
    last_seen_at TIMESTAMP,
    helper TEXT,
    clues TEXT
);
