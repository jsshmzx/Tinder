CREATE TABLE register_questions (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    created_by TEXT,
    question_level TEXT,
    question_type TEXT,
    current_status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
