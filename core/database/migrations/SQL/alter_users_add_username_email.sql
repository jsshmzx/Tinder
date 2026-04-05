-- Add username and email fields to users table for login optimization
-- Users should be able to log in with username or email instead of uuid/real_name

ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT UNIQUE;

-- Create indexes for faster lookups during login
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
