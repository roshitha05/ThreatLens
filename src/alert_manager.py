
import hashlib

from src.database import save_alert


def generate_alert_key(alert):
    """Generate a deterministic identifier for a detection."""
    fields = (
        alert["rule_id"],
        alert["source_ip"],
        alert["username"],
        alert["detected_at"],
    )

    content = "|".join(fields)

    return hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()


def process_alerts(connection, alerts):
    """Assign alert identifiers and store new alerts."""
    saved = 0
    duplicates = 0

    for alert in alerts:
        alert_with_key = {
            **alert,
            "alert_key": generate_alert_key(alert),
        }

        if save_alert(connection, alert_with_key):
            saved += 1
        else:
            duplicates += 1

    return {
        "saved": saved,
        "duplicates": duplicates,
    }


def display_security_report(log_count, alerts, summary, results):
    """Print a security detection report."""
    print("\n" + "=" * 50)
    print("          THREATLENS SECURITY REPORT")
    print("=" * 50)

    print(f"\nLogs Processed: {log_count}")
    print(f"Threats Detected This Run: {len(alerts)}")
    print(f"New Alerts Stored: {results['saved']}")
    print(f"Duplicate Alerts Skipped: {results['duplicates']}")

    print("\nStored Alert Severity Summary:")
    print(f"HIGH:   {summary.get('HIGH', 0)}")
    print(f"MEDIUM: {summary.get('MEDIUM', 0)}")
    print(f"LOW:    {summary.get('LOW', 0)}")

    print("\n" + "-" * 50)

    if not alerts:
        print("No suspicious activity detected.")

    for alert in alerts:
        print(f"\n[{alert['severity']}] {alert['threat_type']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Username: {alert['username']}")
        print(f"Detected At: {alert['detected_at']}")
        print(f"Description: {alert['description']}")

    print("\n" + "=" * 50)
