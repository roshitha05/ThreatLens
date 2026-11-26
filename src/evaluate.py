
from pathlib import Path

from src.log_parser import parse_logs
from src.detection_engine import load_rules, run_detection


def calculate_metrics(tp, fp, fn):
    """Calculate detection precision and recall."""
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0

    return precision, recall


def main():
    project_root = Path(__file__).resolve().parent.parent

    logs = parse_logs(project_root / "data" / "sample_logs.csv")
    rules = load_rules(project_root / "rules")

    alerts = run_detection(logs, rules)

    expected = {
        ("TL-001", "192.168.1.10"),
        ("TL-002", "192.168.1.30"),
        ("TL-003", "192.168.1.40"),
    }

    actual = {
        (alert["rule_id"], alert["source_ip"])
        for alert in alerts
    }

    tp = len(actual & expected)
    fp = len(actual - expected)
    fn = len(expected - actual)

    precision, recall = calculate_metrics(tp, fp, fn)

    print("\n=== THREATLENS DETECTION EVALUATION ===")
    print(f"True Positives: {tp}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall: {recall:.2%}")


if __name__ == "__main__":
    main()
