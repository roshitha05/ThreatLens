
from pathlib import Path

from src.log_parser import parse_logs
from src.detection_engine import load_rules, run_detection


def main():
    project_root = Path(__file__).resolve().parent.parent

    log_file = project_root / "data" / "sample_logs.csv"
    rules_directory = project_root / "rules"

    print("=" * 50)
    print("          THREATLENS SECURITY PIPELINE")
    print("=" * 50)

    logs = parse_logs(log_file)
    rules = load_rules(rules_directory)

    print(f"\n[INFO] Security events loaded: {len(logs)}")
    print(f"[INFO] Active detection rules: {len(rules)}")

    alerts = run_detection(logs, rules)

    print(f"\n[RESULT] Threats detected: {len(alerts)}")

    for alert in alerts:
        print("\n" + "-" * 50)
        print(f"[{alert['severity']}] {alert['threat_type']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Username: {alert['username']}")
        print(f"Detected At: {alert['detected_at']}")
        print(f"Description: {alert['description']}")

    print("\n[INFO] Detection pipeline completed.")


if __name__ == "__main__":
    main()
