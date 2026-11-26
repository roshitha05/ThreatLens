\
from pathlib import Path

from src.log_parser import parse_logs
from src.detection_engine import load_rules, run_detection
from src.database import (
    connect_database,
    get_alert_summary,
)
from src.alert_manager import (
    process_alerts,
    display_security_report,
)


def main():
    project_root = Path(__file__).resolve().parent.parent

    log_file = project_root / "data" / "sample_logs.csv"
    rules_directory = project_root / "rules"
    database_file = project_root / "data" / "threatlens.db"

    print("=" * 50)
    print("          THREATLENS SECURITY PIPELINE")
    print("=" * 50)

    print("\n[INFO] Loading security logs...")
    logs = parse_logs(log_file)

    print("[INFO] Loading detection rules...")
    rules = load_rules(rules_directory)

    print("[INFO] Running threat detection...")
    alerts = run_detection(logs, rules)

    print("[INFO] Connecting to SQLite database...")

    with connect_database(database_file) as connection:
        results = process_alerts(connection, alerts)
        summary = get_alert_summary(connection)

    display_security_report(
        len(logs),
        alerts,
        summary,
        results,
    )

    print("\n[SUCCESS] ThreatLens pipeline completed.")


if __name__ == "__main__":
    main()
