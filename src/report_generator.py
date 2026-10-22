
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def build_report(target, policy_name, findings):
    """Build a structured audit report with a UTC timestamp."""
    return {
        "project": "Secure Network Exposure Auditor",
        "target": target,
        "policy_name": policy_name,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "ports_checked": len(findings),
            "passed": sum(f["status"] == "PASS" for f in findings),
            "alerts": sum(f["status"] == "ALERT" for f in findings),
            "inconclusive": sum(
                f["status"] == "INCONCLUSIVE" for f in findings
            ),
        },
        "findings": findings,
    }


def write_json_report(report, output_path):
    """Write a JSON report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return path


def write_csv_report(report, output_path):
    """Write the findings as a CSV table."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "port",
        "service",
        "expected",
        "observed",
        "status",
        "message",
    ]

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report["findings"])

    return path
