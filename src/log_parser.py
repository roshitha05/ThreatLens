
import csv
import ipaddress
from datetime import datetime
from pathlib import Path


REQUIRED_FIELDS = {
    "timestamp",
    "source_ip",
    "username",
    "event_type",
    "status",
}


def parse_timestamp(value):
    """Convert an ISO 8601 timestamp into a datetime object."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_log(row):
    """Validate a security log entry."""

    for field in REQUIRED_FIELDS:
        if not row.get(field):
            raise ValueError(f"Missing required field: {field}")

    try:
        timestamp = parse_timestamp(row["timestamp"])

        if timestamp.tzinfo is None:
            raise ValueError("Timestamp must include a timezone")

        ipaddress.ip_address(row["source_ip"])

    except ValueError as error:
        raise ValueError(f"Invalid log entry: {error}") from error

    if row["event_type"] not in {"LOGIN", "PRIVILEGE_CHANGE"}:
        raise ValueError("Unsupported event type")

    if row["status"] not in {"SUCCESS", "FAILED"}:
        raise ValueError("Unsupported status")

    return True


def parse_logs(file_path):
    """Read and validate security logs from a CSV file."""

    logs = []
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with file_path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(
            line for line in file if line.strip()
        )

        if not reader.fieldnames or not REQUIRED_FIELDS.issubset(
            reader.fieldnames
        ):
            raise ValueError("CSV is missing required columns")

        for line_number, row in enumerate(reader, start=2):
            try:
                validate_log(row)

                logs.append({
                    "timestamp": parse_timestamp(row["timestamp"]),
                    "source_ip": row["source_ip"],
                    "username": row["username"],
                    "event_type": row["event_type"],
                    "status": row["status"],
                })

            except ValueError as error:
                print(f"[WARNING] Skipping line {line_number}: {error}")

    return logs
