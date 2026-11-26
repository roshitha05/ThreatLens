
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml


def load_rules(rules_directory):
    """Load enabled detection rules from YAML files."""
    rules = []

    for rule_file in sorted(Path(rules_directory).glob("*.yaml")):
        with rule_file.open("r", encoding="utf-8") as file:
            rule = yaml.safe_load(file)

        if not isinstance(rule, dict):
            raise ValueError(f"Invalid YAML rule: {rule_file}")

        if rule.get("enabled", False):
            rules.append(rule)

    return rules


def create_alert(rule, event, description):
    """Create a structured security alert."""
    return {
        "rule_id": rule["id"],
        "threat_type": rule["name"],
        "severity": rule["severity"],
        "source_ip": event["source_ip"],
        "username": event["username"],
        "detected_at": event["timestamp"].isoformat(),
        "description": description,
        "status": "OPEN",
    }


def detect_brute_force(logs, rule):
    """Detect failed login attempts within a rolling time window."""
    grouped = defaultdict(list)
    alerts = []

    for event in logs:
        if (
            event["event_type"] == rule["event_type"]
            and event["status"] == rule["status"]
        ):
            grouped[event[rule["group_by"]]].append(event)

    for source_ip, events in grouped.items():
        events.sort(key=lambda event: event["timestamp"])

        window_start = 0

        for index, event in enumerate(events):
            while (
                event["timestamp"] - events[window_start]["timestamp"]
            ).total_seconds() > rule["time_window"]:
                window_start += 1

            count = index - window_start + 1

            if count == rule["threshold"]:
                description = (
                    f"{count} failed login attempts from "
                    f"{source_ip} within {rule['time_window']} seconds"
                )

                alerts.append(create_alert(rule, event, description))

    return alerts


def detect_unusual_login(logs, rule):
    """Detect successful logins outside configured working hours."""
    alerts = []

    hours = rule["working_hours"]
    timezone = ZoneInfo(hours["timezone"])

    for event in logs:
        if (
            event["event_type"] == rule["event_type"]
            and event["status"] == rule["status"]
        ):
            local_time = event["timestamp"].astimezone(timezone)
            hour = local_time.hour

            if hour < hours["start"] or hour >= hours["end"]:
                description = (
                    f"Login outside working hours at "
                    f"{local_time.strftime('%H:%M %Z')}"
                )

                alerts.append(create_alert(rule, event, description))

    return alerts


def detect_privilege_change(logs, rule):
    """Detect successful privileged account changes."""
    alerts = []

    for event in logs:
        if (
            event["event_type"] == rule["event_type"]
            and event["status"] == rule["status"]
        ):
            alerts.append(
                create_alert(
                    rule,
                    event,
                    "Successful privileged account modification detected",
                )
            )

    return alerts


DETECTORS = {
    "TL-001": detect_brute_force,
    "TL-002": detect_unusual_login,
    "TL-003": detect_privilege_change,
}


def run_detection(logs, rules):
    """Execute enabled detection rules against parsed logs."""
    alerts = []

    for rule in rules:
        detector = DETECTORS.get(rule["id"])

        if detector is None:
            raise ValueError(f"Unsupported detection rule: {rule['id']}")

        alerts.extend(detector(logs, rule))

    return sorted(
        alerts,
        key=lambda alert: alert["detected_at"],
    )
