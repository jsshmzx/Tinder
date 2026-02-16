CREATE TABLE IF NOT EXISTS stores_and_restaurants (
    id SERIAL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    location TEXT,
    likes INTEGER DEFAULT 0,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    ratings DECIMAL(3, 2),
    status TEXT
);
