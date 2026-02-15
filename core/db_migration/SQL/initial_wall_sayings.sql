CREATE TABLE IF NOT EXISTS wall_sayings (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    author_uuid TEXT NOT NULL,
    content TEXT,
    saying_status TEXT,
    saying_type TEXT,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    other_info JSONB,
    likes INTEGER DEFAULT 0,
    share_count INTEGER DEFAULT 0,
    views INTEGER DEFAULT 0
);