CREATE TABLE IF NOT EXISTS relations (
    id SERIAL PRIMARY KEY,
    tags_uuid TEXT NOT NULL,
    related_uuid TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
