CREATE TABLE IF NOT EXISTS personal_logs (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    user_uuid TEXT NOT NULL,
    log_level TEXT,
    log_type TEXT,
    content TEXT,
    created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
