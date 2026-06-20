"""Unit tests — core.helper.CustomLog.index.CustomLog"""

import pytest

from core.helper.CustomLog.index import CustomLog

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
    LOG_CLS("SUCCESS", "should not appear", print_out=False, sid=False)
    out = capsys.readouterr().out
    assert out == ""

