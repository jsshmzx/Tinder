-- 为 personal_logs 表补充结构化日志字段
-- 新增事件类型、状态、操作对象、变更前后数据、请求信息、错误信息、追踪字段等

ALTER TABLE personal_logs
    ADD COLUMN IF NOT EXISTS event_type TEXT,
    ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'SUCCESS',
    ADD COLUMN IF NOT EXISTS target_type TEXT,
    ADD COLUMN IF NOT EXISTS target_id TEXT,
    ADD COLUMN IF NOT EXISTS target_name TEXT,
    ADD COLUMN IF NOT EXISTS before_data JSONB,
    ADD COLUMN IF NOT EXISTS after_data JSONB,
    ADD COLUMN IF NOT EXISTS operation_result TEXT,
    ADD COLUMN IF NOT EXISTS client_ip TEXT,
    ADD COLUMN IF NOT EXISTS user_agent TEXT,
    ADD COLUMN IF NOT EXISTS request_method TEXT,
    ADD COLUMN IF NOT EXISTS request_url TEXT,
    ADD COLUMN IF NOT EXISTS trace_id TEXT,
    ADD COLUMN IF NOT EXISTS error_code TEXT,
    ADD COLUMN IF NOT EXISTS error_msg TEXT,
    ADD COLUMN IF NOT EXISTS extra_data JSONB;

CREATE INDEX IF NOT EXISTS idx_personal_logs_user_uuid ON personal_logs(user_uuid);
CREATE INDEX IF NOT EXISTS idx_personal_logs_event_type ON personal_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_personal_logs_status ON personal_logs(status);
CREATE INDEX IF NOT EXISTS idx_personal_logs_target_type ON personal_logs(target_type);
CREATE INDEX IF NOT EXISTS idx_personal_logs_target_id ON personal_logs(target_id);
CREATE INDEX IF NOT EXISTS idx_personal_logs_trace_id ON personal_logs(trace_id);
CREATE INDEX IF NOT EXISTS idx_personal_logs_created_at ON personal_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_personal_logs_log_type ON personal_logs(log_type);
