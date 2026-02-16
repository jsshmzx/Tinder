CREATE TABLE IF NOT EXISTS wall_looking_for (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    status TEXT,
    real_status TEXT,
    seeker TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    type TEXT,
    last_seen_time TIMESTAMP,
    helper TEXT,
    clues TEXT
);
