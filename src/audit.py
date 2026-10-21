
import argparse
from pathlib import Path

from minimap import PORTS, check_port, validate_target
from policy_auditor import audit_results, load_policy


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = PROJECT_ROOT / "policies" / "expected_services.json"


def main():
    parser = argparse.ArgumentParser(
        description="Scan an authorized private IPv4 target and audit its TCP ports."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="127.0.0.1",
        help="Authorized loopback or private IPv4 address"
    )
    parser.add_argument(
        "--policy",
        default=str(DEFAULT_POLICY),
        help="Path to expected-services JSON policy"
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

        for port in policy["expected_ports"]:
            port = int(port)
            result = check_port(target, port)
            scan_results[port] = result
            print(f"Scanned port {port}: {result}")

        findings = audit_results(scan_results, policy)

        print("\nSECURITY POLICY AUDIT")
        print("-" * 78)
        print(f"{'PORT':<8}{'SERVICE':<22}{'EXPECTED':<12}{'OBSERVED':<22}{'STATUS'}")
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

        print("-" * 78)
        alerts = sum(item["status"] == "ALERT" for item in findings)
        inconclusive = sum(
            item["status"] == "INCONCLUSIVE" for item in findings
        )
        print(
            f"Summary: {len(findings)} ports checked, "
            f"{alerts} alert(s), {inconclusive} inconclusive."
        )

    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
