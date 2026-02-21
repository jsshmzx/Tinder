"""Tests for core.helper.ContainerCustomLog.index.custom_log."""

from core.helper.ContainerCustomLog.index import custom_log


def test_success_level_output(capsys):
    custom_log("SUCCESS", "all good")
    captured = capsys.readouterr()
    assert "[SUCCESS]" in captured.out
    assert "all good" in captured.out


def test_warning_level_output(capsys):
    custom_log("WARNING", "be careful")
    captured = capsys.readouterr()
    assert "[WARNING]" in captured.out
    assert "be careful" in captured.out


def test_error_level_output(capsys):
    custom_log("ERROR", "something failed")
    captured = capsys.readouterr()
    assert "[ERROR]" in captured.out
    assert "something failed" in captured.out


def test_level_is_case_insensitive(capsys):
    custom_log("success", "lower case level")
    captured = capsys.readouterr()
    assert "[SUCCESS]" in captured.out
    assert "lower case level" in captured.out


def test_unknown_level_uses_level_name_as_label(capsys):
    custom_log("DEBUG", "debug info")
    captured = capsys.readouterr()
    assert "[DEBUG]" in captured.out
    assert "debug info" in captured.out
