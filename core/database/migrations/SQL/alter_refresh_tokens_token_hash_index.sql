-- 为 refresh_tokens.token_hash 添加索引（高频查询字段）
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens (token_hash);
