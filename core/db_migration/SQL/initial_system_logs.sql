CREATE TABLE IF NOT EXISTS system_logs (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    level TEXT,
    log_type TEXT,
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    being_flagged BOOLEAN DEFAULT FALSE,
    content TEXT,
    version TEXT
);
