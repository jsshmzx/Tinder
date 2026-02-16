CREATE TABLE IF NOT EXISTS system_logs (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    log_level TEXT,
    log_type TEXT,
    created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    being_flagged BOOLEAN DEFAULT FALSE,
    content TEXT,
    system_version TEXT
);
