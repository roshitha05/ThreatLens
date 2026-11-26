
from src.database import (
    connect_database,
    get_alerts,
    get_alert_summary,
)
from src.alert_manager import (
    generate_alert_key,
    process_alerts,
)


def sample_alert():
    return {
        "rule_id": "TL-001",
        "threat_type": "Brute Force Detection",
        "severity": "HIGH",
        "source_ip": "192.168.1.10",
        "username": "admin",
        "detected_at": "2026-11-25T10:00:15+00:00",
        "description": "5 failed login attempts",
        "status": "OPEN",
    }


def test_alert_key_is_deterministic():
    alert = sample_alert()

    assert generate_alert_key(alert) == generate_alert_key(alert)


def test_save_alert(tmp_path):
    connection = connect_database(tmp_path / "test.db")

    try:
        result = process_alerts(connection, [sample_alert()])

        assert result["saved"] == 1
        assert len(get_alerts(connection)) == 1
    finally:
        connection.close()


def test_duplicate_alert_prevention(tmp_path):
    connection = connect_database(tmp_path / "test.db")

    try:
        process_alerts(connection, [sample_alert()])
        result = process_alerts(connection, [sample_alert()])

        assert result["saved"] == 0
        assert result["duplicates"] == 1
        assert len(get_alerts(connection)) == 1
    finally:
        connection.close()


def test_alert_summary(tmp_path):
    connection = connect_database(tmp_path / "test.db")

    try:
        process_alerts(connection, [sample_alert()])

        summary = get_alert_summary(connection)

        assert summary["HIGH"] == 1
    finally:
        connection.close()
