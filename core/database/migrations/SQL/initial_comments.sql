CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    status TEXT,
    comment_place TEXT,
    author TEXT,
    relations TEXT,
    comment_place_uuid TEXT,
    ip_address TEXT,
    user_agent TEXT,
    location TEXT,
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
