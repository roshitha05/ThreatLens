
import pytest

from src.log_parser import parse_logs, validate_log


def test_valid_log():
    log = {
        "timestamp": "2026-11-25T10:00:01Z",
        "source_ip": "192.168.1.10",
        "username": "admin",
        "event_type": "LOGIN",
        "status": "FAILED",
    }

    assert validate_log(log) is True


def test_invalid_ip():
    log = {
        "timestamp": "2026-11-25T10:00:01Z",
        "source_ip": "999.999.999.999",
        "username": "admin",
        "event_type": "LOGIN",
        "status": "FAILED",
    }

    with pytest.raises(ValueError):
        validate_log(log)


def test_missing_username():
    log = {
        "timestamp": "2026-11-25T10:00:01Z",
        "source_ip": "192.168.1.10",
        "username": "",
        "event_type": "LOGIN",
        "status": "FAILED",
    }

    with pytest.raises(ValueError):
        validate_log(log)


def test_parse_csv(tmp_path):
    file = tmp_path / "test_logs.csv"

    file.write_text(
        "timestamp,source_ip,username,event_type,status\n"
        "2026-11-25T10:00:01Z,192.168.1.10,admin,LOGIN,FAILED\n"
    )

    logs = parse_logs(file)

    assert len(logs) == 1
    assert logs[0]["username"] == "admin"
    assert logs[0]["status"] == "FAILED"


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        parse_logs("nonexistent_logs.csv")
