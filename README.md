# ThreatLens : Automated Security Threat Detection Pipeline

ThreatLens is a Python-based cybersecurity project that analyzes security logs to identify potentially suspicious activity. It uses configurable YAML rules to detect patterns such as repeated failed login attempts, logins outside working hours, and privileged account changes.

I built this project to gain more hands-on experience with security log analysis, detection engineering, and Python automation. I also wanted to understand how a basic rule-based detection pipeline works, from processing raw logs to generating and storing security alerts.

## Features

- **Security Log Parsing:** Reads CSV security logs and validates timestamps, IP addresses, and event information.
- **Rule-Based Threat Detection:** Uses YAML configuration files to define detection conditions and severity levels.
- **Brute-Force Detection:** Identifies repeated failed login attempts from the same IP address within a specified time window.
- **Unusual Login Detection:** Flags successful logins outside configured working hours.
- **Privileged Account Monitoring:** Detects successful privileged account change events.
- **Alert Management:** Generates structured security alerts and stores them in SQLite.
- **Duplicate Prevention:** Uses deterministic alert identifiers to avoid storing the same detection multiple times.
- **Detection Evaluation:** Calculates precision and recall against a small labelled synthetic dataset.
- **Automated Testing:** Uses pytest and GitHub Actions to validate the detection pipeline.

## Tech Stack

| Technology | Purpose |
|---|---|
| Python | Log processing, detection logic, and automation |
| PyYAML | Loading configurable detection rules |
| SQLite | Storing and retrieving security alerts |
| pytest | Automated testing |
| GitHub Actions | Continuous integration |

## How It Works

ThreatLens follows a simple detection pipeline:

```text
Security Logs (CSV)
        |
        v
Log Parsing & Validation
        |
        v
YAML Detection Rules
        |
        v
Threat Detection Engine
        |
        v
Alert Generation
        |
        v
SQLite Database
        |
        v
Security Report
```

The log parser first reads and validates security events. The detection engine then evaluates these events against the enabled YAML rules.

When an event or sequence of events matches a rule, ThreatLens generates an alert containing details such as the detection type, severity, source IP, username, and timestamp.

Alerts are stored in SQLite and summarized in the terminal.

## Detection Rules

ThreatLens currently supports three detection rules.

| Rule ID | Detection | Condition | Severity |
|---|---|---|---|
| TL-001 | Brute Force Detection | 5 failed login attempts from one IP within 60 seconds | HIGH |
| TL-002 | Unusual Login Detection | Successful login outside 09:00–18:00 SGT | MEDIUM |
| TL-003 | Privileged Account Activity | Successful privilege-change event | HIGH |

Detection conditions are configured using YAML files in the `rules/` directory.

For example, the brute-force detection rule allows the failed-login threshold and time window to be adjusted without modifying the Python detection logic.

## MITRE ATT&CK Mapping

I included MITRE ATT&CK references to better understand how the detection rules relate to common adversary techniques.

| Detection Rule | MITRE ATT&CK Technique | Technique ID |
|---|---|---|
| Brute Force Detection | Brute Force | T1110 |
| Unusual Login Detection | Valid Accounts | T1078 |
| Privileged Account Activity | Account Manipulation | T1098 |

These mappings provide context for the detected behavior. They do not confirm that an attack occurred.

For example, logging in outside working hours may be legitimate, but it can still be useful to flag the event for further investigation.

## Project Structure

```text
ThreatLens/
├── data/
│   └── sample_logs.csv
├── rules/
│   ├── brute_force.yaml
│   ├── unusual_login.yaml
│   └── privilege_escalation.yaml
├── src/
│   ├── log_parser.py
│   ├── detection_engine.py
│   ├── alert_manager.py
│   ├── database.py
│   ├── evaluate.py
│   └── main.py
├── tests/
│   ├── test_log_parser.py
│   ├── test_detection_engine.py
│   └── test_alert_manager.py
├── .github/workflows/
│   └── ci.yml
├── requirements.txt
└── README.md
```

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/roshitha05/ThreatLens.git
cd ThreatLens
```

### 2. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the detection pipeline

```bash
python -m src.main
```

ThreatLens will process the sample security logs, evaluate the enabled detection rules, and generate a security report.

### 5. Run automated tests

```bash
python -m pytest tests/ -v
```

### 6. Run detection evaluation

```bash
python -m src.evaluate
```

## Testing and Evaluation

I used pytest to test the log parser, detection engine, and alert management functionality.

The tests cover scenarios including:

- Valid and invalid security log entries
- Missing CSV fields and blank lines
- Brute-force detection thresholds
- Failed logins outside the configured time window
- Multiple login attempts from different IP addresses
- Successful logins that should not trigger brute-force alerts
- Duplicate alert prevention
- SQLite alert storage and retrieval

I also created a small synthetic dataset containing both suspicious and normal security events.

The evaluation script compares detected alerts against expected findings and calculates precision and recall.

The dataset is intentionally small, so these results are useful for checking the implementation but should not be treated as a measure of real-world detection performance.

GitHub Actions automatically runs the tests, detection pipeline, and evaluation script whenever changes are pushed to the main branch or a pull request is opened.

## Limitations

ThreatLens is a learning project and is not intended to replace a production security monitoring solution.

Current limitations include:

- Log ingestion is limited to CSV files.
- Detection is batch-based rather than real-time.
- The engine supports three predefined detection strategies.
- The evaluation uses a small synthetic dataset.
- Some detection rules may flag legitimate activity.
- Alert correlation and investigation capabilities are limited.

## Future Improvements

Some features I would like to explore in future versions include:

- Supporting Linux authentication logs and other log formats
- Adding more detection rules and attack scenarios
- Evaluating detection performance using larger labelled datasets
- Improving alert correlation and reducing false positives
- Adding threat intelligence enrichment
- Building a simple interface for reviewing detected alerts

## What I Learned

Through this project, I gained practical experience in building a rule-based security detection pipeline using Python.

It helped me understand how authentication events can be analyzed, how detection conditions can be separated from application logic using YAML, and how security findings can be stored for further investigation.

I also gained experience with automated testing, handling invalid log data, and using GitHub Actions to verify that the project continues to work after code changes.

## License

This project is licensed under the MIT License.
