
from datetime import datetime, timedelta, timezone

from src.detection_engine import (
    detect_brute_force,
    detect_unusual_login,
    detect_privilege_change,
)


BASE_TIME = datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc)


def make_event(seconds=0, ip="192.168.1.10",
               event_type="LOGIN", status="FAILED"):
    return {
        "timestamp": BASE_TIME + timedelta(seconds=seconds),
        "source_ip": ip,
        "username": "admin",
        "event_type": event_type,
        "status": status,
    }


BRUTE_FORCE_RULE = {
    "id": "TL-001",
    "name": "Brute Force Detection",
    "severity": "HIGH",
    "event_type": "LOGIN",
    "status": "FAILED",
    "group_by": "source_ip",
    "threshold": 5,
    "time_window": 60,
}


def test_brute_force_detected():
    logs = [make_event(seconds=i * 5) for i in range(5)]

    alerts = detect_brute_force(logs, BRUTE_FORCE_RULE)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"


def test_four_failed_logins_no_alert():
    logs = [make_event(seconds=i * 5) for i in range(4)]

    assert detect_brute_force(logs, BRUTE_FORCE_RULE) == []


def test_failures_outside_window():
    logs = [make_event(seconds=i * 120) for i in range(5)]

    assert detect_brute_force(logs, BRUTE_FORCE_RULE) == []


def test_different_ips_no_alert():
    logs = [
        make_event(seconds=i, ip=f"192.168.1.{i + 1}")
        for i in range(5)
    ]

    assert detect_brute_force(logs, BRUTE_FORCE_RULE) == []


def test_unusual_login():
    rule = {
        "id": "TL-002",
        "name": "Unusual Login Detection",
        "severity": "MEDIUM",
        "event_type": "LOGIN",
        "status": "SUCCESS",
        "working_hours": {
            "start": 9,
            "end": 18,
            "timezone": "Asia/Singapore",
        },
    }

    # 20:00 UTC = 04:00 Singapore time (next day)
    event = make_event(
        seconds=36000,
        status="SUCCESS",
    )

    alerts = detect_unusual_login([event], rule)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "MEDIUM"


def test_privilege_change():
    rule = {
        "id": "TL-003",
        "name": "Privileged Account Activity",
        "severity": "HIGH",
        "event_type": "PRIVILEGE_CHANGE",
        "status": "SUCCESS",
    }

    event = make_event(
        event_type="PRIVILEGE_CHANGE",
        status="SUCCESS",
    )

    alerts = detect_privilege_change([event], rule)

    assert len(alerts) == 1


def test_sustained_brute_force_single_alert():
    """A sustained burst should produce only one alert."""
    logs = [
        make_event(seconds=i * 5)
        for i in range(10)
    ]

    alerts = detect_brute_force(logs, BRUTE_FORCE_RULE)

    assert len(alerts) == 1


def test_separate_brute_force_bursts():
    """Separated attack bursts should generate separate alerts."""
    first_burst = [
        make_event(seconds=i * 5)
        for i in range(5)
    ]

    second_burst = [
        make_event(seconds=600 + i * 5)
        for i in range(5)
    ]

    alerts = detect_brute_force(
        first_burst + second_burst,
        BRUTE_FORCE_RULE
    )

    assert len(alerts) == 2


def test_unsorted_logs():
    """Detection must work even if events are out of order."""
    logs = [
        make_event(seconds=i * 5)
        for i in range(5)
    ]

    logs.reverse()

    alerts = detect_brute_force(logs, BRUTE_FORCE_RULE)

    assert len(alerts) == 1


def test_successful_logins_not_brute_force():
    """Successful logins must not trigger brute-force detection."""
    logs = [
        make_event(seconds=i * 5, status="SUCCESS")
        for i in range(10)
    ]

    alerts = detect_brute_force(logs, BRUTE_FORCE_RULE)

    assert alerts == []


def test_detection_threshold_boundary():
    """Five failures exactly 60 seconds apart should count."""
    logs = [
        make_event(seconds=seconds)
        for seconds in [0, 15, 30, 45, 60]
    ]

    alerts = detect_brute_force(logs, BRUTE_FORCE_RULE)

    assert len(alerts) == 1
