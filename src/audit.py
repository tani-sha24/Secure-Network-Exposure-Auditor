
import argparse
from datetime import datetime, timezone
from pathlib import Path

from minimap import check_port, validate_target
from policy_auditor import audit_results, load_policy
from report_generator import (
    build_report,
    write_csv_report,
    write_json_report,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = PROJECT_ROOT / "policies" / "expected_services.json"
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports"


def main():
    parser = argparse.ArgumentParser(
        description="Scan an authorized private IPv4 target and audit its TCP ports."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="127.0.0.1",
        help="Authorized loopback or private IPv4 address",
    )
    parser.add_argument(
        "--policy",
        default=str(DEFAULT_POLICY),
        help="Path to expected-services JSON policy",
    )
    parser.add_argument(
        "--report-dir",
        default=str(DEFAULT_REPORT_DIR),
        help="Directory for generated JSON and CSV reports",
    )
    args = parser.parse_args()

    try:
        target = validate_target(args.target)
        policy = load_policy(args.policy)

        if target != policy.get("target"):
            parser.error(
                f"Target {target} does not match policy target "
                f"{policy.get('target')!r}"
            )

        scan_results = {}

        for port_text in policy["expected_ports"]:
            port = int(port_text)
            result = check_port(target, port)
            scan_results[port] = result
            print(f"Scanned port {port}: {result}")

        findings = audit_results(scan_results, policy)

        print("\nSECURITY POLICY AUDIT")
        print("-" * 78)
        print(
            f"{'PORT':<8}{'SERVICE':<22}{'EXPECTED':<12}"
            f"{'OBSERVED':<22}{'STATUS'}"
        )
        print("-" * 78)

        for finding in findings:
            print(
                f"{finding['port']:<8}"
                f"{finding['service']:<22}"
                f"{finding['expected']:<12}"
                f"{finding['observed']:<22}"
                f"{finding['status']}"
            )
            print(f"  {finding['message']}")

        report = build_report(
            target=target,
            policy_name=policy["policy_name"],
            findings=findings,
        )

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_dir = Path(args.report_dir)

        json_path = write_json_report(
            report, report_dir / f"audit_{timestamp}.json"
        )
        csv_path = write_csv_report(
            report, report_dir / f"audit_{timestamp}.csv"
        )

        summary = report["summary"]
        print("-" * 78)
        print(
            f"Summary: {summary['ports_checked']} ports checked, "
            f"{summary['alerts']} alert(s), "
            f"{summary['inconclusive']} inconclusive."
        )
        print(f"Passed: {summary['passed']}")
        print(f"JSON report: {json_path}")
        print(f"CSV report:  {csv_path}")

    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()

