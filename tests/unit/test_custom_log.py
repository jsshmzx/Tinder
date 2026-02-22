"""Unit tests — core.helper.ContainerCustomLog.index.custom_log"""

import pytest

from core.helper.ContainerCustomLog.index import custom_log


# ---------------------------------------------------------------------------
# SUCCESS level
# ---------------------------------------------------------------------------

def test_success_label_present(capsys):
    print("\n[TEST] custom_log('SUCCESS', ...) 应输出 [SUCCESS] 标签")
    custom_log("SUCCESS", "all good")
    out = capsys.readouterr().out
    assert "[SUCCESS]" in out


def test_success_content_present(capsys):
    print("\n[TEST] custom_log('SUCCESS', ...) 应包含传入的消息内容")
    custom_log("SUCCESS", "everything is fine")
    out = capsys.readouterr().out
    assert "everything is fine" in out


# ---------------------------------------------------------------------------
# WARNING level
# ---------------------------------------------------------------------------

def test_warning_label_present(capsys):
    print("\n[TEST] custom_log('WARNING', ...) 应输出 [WARNING] 标签")
    custom_log("WARNING", "be careful")
    out = capsys.readouterr().out
    assert "[WARNING]" in out


def test_warning_content_present(capsys):
    print("\n[TEST] custom_log('WARNING', ...) 应包含传入的消息内容")
    custom_log("WARNING", "watch out")
    out = capsys.readouterr().out
    assert "watch out" in out


# ---------------------------------------------------------------------------
# ERROR level
# ---------------------------------------------------------------------------

def test_error_label_present(capsys):
    print("\n[TEST] custom_log('ERROR', ...) 应输出 [ERROR] 标签")
    custom_log("ERROR", "something failed")
    out = capsys.readouterr().out
    assert "[ERROR]" in out


def test_error_content_present(capsys):
    print("\n[TEST] custom_log('ERROR', ...) 应包含传入的消息内容")
    custom_log("ERROR", "critical failure")
    out = capsys.readouterr().out
    assert "critical failure" in out


# ---------------------------------------------------------------------------
# Case-insensitivity
# ---------------------------------------------------------------------------

def test_level_case_insensitive_lower(capsys):
    print("\n[TEST] 日志级别不区分大小写：'success' 应等同于 'SUCCESS'")
    custom_log("success", "lowercase level")
    out = capsys.readouterr().out
    assert "[SUCCESS]" in out


def test_level_case_insensitive_mixed(capsys):
    print("\n[TEST] 日志级别不区分大小写：'Warning' 应等同于 'WARNING'")
    custom_log("Warning", "mixed case level")
    out = capsys.readouterr().out
    assert "[WARNING]" in out


# ---------------------------------------------------------------------------
# Unknown level falls back to level name
# ---------------------------------------------------------------------------

def test_unknown_level_uses_level_name_as_label(capsys):
    print("\n[TEST] 未知日志级别应以级别名称作为标签输出")
    custom_log("DEBUG", "debug info")
    out = capsys.readouterr().out
    assert "[DEBUG]" in out
    assert "debug info" in out
