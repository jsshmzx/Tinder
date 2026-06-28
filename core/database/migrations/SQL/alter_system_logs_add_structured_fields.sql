-- 为 system_logs 表补充结构化日志字段
-- 新增事件类型、状态、来源信息、请求信息、错误信息、追踪字段等

ALTER TABLE system_logs
    ADD COLUMN IF NOT EXISTS event_type TEXT,
    ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'SUCCESS',
    ADD COLUMN IF NOT EXISTS severity TEXT,
    ADD COLUMN IF NOT EXISTS service_name TEXT,
    ADD COLUMN IF NOT EXISTS host_name TEXT,
    ADD COLUMN IF NOT EXISTS host_ip TEXT,
    ADD COLUMN IF NOT EXISTS process_id TEXT,
    ADD COLUMN IF NOT EXISTS trace_id TEXT,
    ADD COLUMN IF NOT EXISTS client_ip TEXT,
    ADD COLUMN IF NOT EXISTS user_agent TEXT,
    ADD COLUMN IF NOT EXISTS request_method TEXT,
    ADD COLUMN IF NOT EXISTS request_url TEXT,
    ADD COLUMN IF NOT EXISTS error_code TEXT,
    ADD COLUMN IF NOT EXISTS error_msg TEXT,
    ADD COLUMN IF NOT EXISTS metric_value TEXT,
    ADD COLUMN IF NOT EXISTS extra_data JSONB;

CREATE INDEX IF NOT EXISTS idx_system_logs_event_type ON system_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_system_logs_status ON system_logs(status);
CREATE INDEX IF NOT EXISTS idx_system_logs_severity ON system_logs(severity);
CREATE INDEX IF NOT EXISTS idx_system_logs_service_name ON system_logs(service_name);
CREATE INDEX IF NOT EXISTS idx_system_logs_trace_id ON system_logs(trace_id);
CREATE INDEX IF NOT EXISTS idx_system_logs_client_ip ON system_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_system_logs_created_at ON system_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_system_logs_log_type ON system_logs(log_type);
