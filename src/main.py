
from pathlib import Path
from src.log_parser import parse_logs


def main():
    print("=" * 45)
    print("       THREATLENS SECURITY PIPELINE")
    print("=" * 45)

    project_root = Path(__file__).resolve().parent.parent
    log_file = project_root / "data" / "sample_logs.csv"

    print("\n[INFO] Loading security logs...")

    logs = parse_logs(log_file)

    print(f"[SUCCESS] {len(logs)} valid security events loaded.\n")

    for log in logs:
        print(
            f"[EVENT] {log['timestamp']} | "
            f"{log['source_ip']} | "
            f"{log['username']} | "
            f"{log['event_type']} | "
            f"{log['status']}"
        )

    print("\n[INFO] Log parsing completed successfully.")


if __name__ == "__main__":
    main()
