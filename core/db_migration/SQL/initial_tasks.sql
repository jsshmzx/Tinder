CREATE TABLE IF NOT EXISTS tasks (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    content TEXT,
    parts TEXT,
    assigner TEXT,
    status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
