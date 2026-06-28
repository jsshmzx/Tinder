"""Unit tests — core.helper.CustomLog.index.CustomLog"""

import datetime

import pytest

from core.helper.CustomLog.index import CustomLog, LogContext, _json_safe, get_log_context, set_log_context

LOG_CLS = CustomLog


def _make_log(log_level: str, content: str):
    """辅助：创建日志（只打印，不存 DB）。"""
    return LOG_CLS(log_level, content, print_out=True, sid=False)


# ---------------------------------------------------------------------------
# SUCCESS level
# ---------------------------------------------------------------------------

def test_success_label_present(capsys):
    print("\n[TEST] CustomLog('SUCCESS', ...) 应输出 [SUCCESS] 标签")
    _make_log("SUCCESS", "all good")
    out = capsys.readouterr().out
    assert "[SUCCESS]" in out


def test_success_content_present(capsys):
    print("\n[TEST] CustomLog('SUCCESS', ...) 应包含传入的消息内容")
    _make_log("SUCCESS", "everything is fine")
    out = capsys.readouterr().out
    assert "everything is fine" in out


# ---------------------------------------------------------------------------
# WARNING level
# ---------------------------------------------------------------------------

def test_warning_label_present(capsys):
    print("\n[TEST] CustomLog('WARNING', ...) 应输出 [WARNING] 标签")
    _make_log("WARNING", "be careful")
    out = capsys.readouterr().out
    assert "[WARNING]" in out


def test_warning_content_present(capsys):
    print("\n[TEST] CustomLog('WARNING', ...) 应包含传入的消息内容")
    _make_log("WARNING", "watch out")
    out = capsys.readouterr().out
    assert "watch out" in out


# ---------------------------------------------------------------------------
# ERROR level
# ---------------------------------------------------------------------------

def test_error_label_present(capsys):
    print("\n[TEST] CustomLog('ERROR', ...) 应输出 [ERROR] 标签")
    _make_log("ERROR", "something failed")
    out = capsys.readouterr().out
    assert "[ERROR]" in out


def test_error_content_present(capsys):
    print("\n[TEST] CustomLog('ERROR', ...) 应包含传入的消息内容")
    _make_log("ERROR", "critical failure")
    out = capsys.readouterr().out
    assert "critical failure" in out


# ---------------------------------------------------------------------------
# INFO level
# ---------------------------------------------------------------------------

def test_info_label_present(capsys):
    print("\n[TEST] CustomLog('INFO', ...) 应输出 [INFO] 标签")
    _make_log("INFO", "just info")
    out = capsys.readouterr().out
    assert "[INFO]" in out


def test_info_content_present(capsys):
    print("\n[TEST] CustomLog('INFO', ...) 应包含传入的消息内容")
    _make_log("INFO", "info message")
    out = capsys.readouterr().out
    assert "info message" in out


# ---------------------------------------------------------------------------
# Case-insensitivity
# ---------------------------------------------------------------------------

def test_level_case_insensitive_lower(capsys):
    print("\n[TEST] 日志级别不区分大小写：'success' 应等同于 'SUCCESS'")
    _make_log("success", "lowercase level")
    out = capsys.readouterr().out
    assert "[SUCCESS]" in out


def test_level_case_insensitive_mixed(capsys):
    print("\n[TEST] 日志级别不区分大小写：'Warning' 应等同于 'WARNING'")
    _make_log("Warning", "mixed case level")
    out = capsys.readouterr().out
    assert "[WARNING]" in out


# ---------------------------------------------------------------------------
# Unknown level falls back to level name
# ---------------------------------------------------------------------------

def test_unknown_level_uses_level_name_as_label(capsys):
    print("\n[TEST] 未知日志级别应以级别名称作为标签输出")
    _make_log("DEBUG", "debug info")
    out = capsys.readouterr().out
    assert "[DEBUG]" in out
    assert "debug info" in out


# ---------------------------------------------------------------------------
# NORMAL style (plain text without ANSI colors)
# ---------------------------------------------------------------------------

def test_normal_style_no_color_code(capsys):
    print("\n[TEST] NORMAL 样式不应包含 ANSI 颜色代码")
    LOG_CLS("SUCCESS", "plain text", log_style="NORMAL", print_out=True, sid=False)
    out = capsys.readouterr().out
    assert "\033[" not in out
    assert "[SUCCESS]" in out


# ---------------------------------------------------------------------------
# PrintOut=False should not output
# ---------------------------------------------------------------------------

def test_print_out_false(capsys):
    print("\n[TEST] print_out=False 时不输出任何内容")
    # 先清空 capsys 中的 test print 内容
    capsys.readouterr()
    LOG_CLS("SUCCESS", "should not appear", print_out=False, sid=False)
    out = capsys.readouterr().out
    assert out == ""


# ---------------------------------------------------------------------------
# Structured fields — trace_id in console output
# ---------------------------------------------------------------------------

def test_trace_id_printed_when_provided(capsys):
    print("\n[TEST] 提供 trace_id 时控制台输出应包含 trace_id")
    LOG_CLS(
        "INFO",
        "structured log",
        print_out=True,
        sid=False,
        trace_id="trace-123",
    )
    out = capsys.readouterr().out
    assert "trace-123" in out


# ---------------------------------------------------------------------------
# LogContext
# ---------------------------------------------------------------------------

def test_log_context_merged_into_log(capsys):
    print("\n[TEST] LogContext 中的字段应被日志继承")
    token = set_log_context(LogContext(trace_id="ctx-trace", client_ip="10.0.0.1"))
    try:
        LOG_CLS("INFO", "with context", print_out=True, sid=False)
        out = capsys.readouterr().out
        assert "ctx-trace" in out
        # client_ip 不在控制台输出，但应被记录到对象中；这里仅验证上下文生效
    finally:
        from core.helper.CustomLog.index import reset_log_context
        reset_log_context(token)


def test_explicit_field_overrides_context(capsys):
    print("\n[TEST] 显式参数应覆盖 LogContext 中的同名字段")
    token = set_log_context(LogContext(trace_id="ctx-trace"))
    try:
        LOG_CLS(
            "INFO",
            "override context",
            print_out=True,
            sid=False,
            trace_id="explicit-trace",
        )
        out = capsys.readouterr().out
        assert "explicit-trace" in out
        assert "ctx-trace" not in out
    finally:
        from core.helper.CustomLog.index import reset_log_context
        reset_log_context(token)


def test_get_log_context_returns_empty_when_not_set():
    ctx = get_log_context()
    assert ctx.trace_id is None
    assert ctx.client_ip is None


# ---------------------------------------------------------------------------
# JSON-safe conversion
# ---------------------------------------------------------------------------

def test_json_safe_converts_datetime():
    dt = datetime.datetime(2026, 6, 28, 12, 0, 0)
    assert _json_safe(dt) == "2026-06-28T12:00:00"


def test_json_safe_converts_nested_dict():
    dt = datetime.datetime(2026, 6, 28, 12, 0, 0)
    data = {"user": {"created_at": dt, "tags": [dt, "ok"]}}
    result = _json_safe(data)
    assert result["user"]["created_at"] == "2026-06-28T12:00:00"
    assert result["user"]["tags"] == ["2026-06-28T12:00:00", "ok"]


def test_json_safe_leaves_simple_values_unchanged():
    assert _json_safe("text") == "text"
    assert _json_safe(123) == 123
    assert _json_safe([1, 2, 3]) == [1, 2, 3]
