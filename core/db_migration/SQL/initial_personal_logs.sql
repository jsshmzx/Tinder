CREATE TABLE IF NOT EXISTS personal_logs (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    user_uuid TEXT,
    level TEXT,
    log_type TEXT,
    content TEXT,
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
