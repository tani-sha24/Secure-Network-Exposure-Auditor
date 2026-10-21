
import json
from pathlib import Path


def audit_results(scan_results, policy):
    """Compare observed port states with the expected policy."""
    findings = []

    expected_ports = policy["expected_ports"]

    for port_text, details in expected_ports.items():
        port = int(port_text)
        expected = details["expected_state"].upper()
        service = details["service"]

        observed = scan_results.get(port, "NOT SCANNED").upper()

        if observed == "NO RESPONSE / ERROR" or observed.startswith(
            "NO RESPONSE"
        ):
            status = "INCONCLUSIVE"
            message = "Could not determine the port state"

        elif observed == "NOT SCANNED":
            status = "INCONCLUSIVE"
            message = "Port was not included in the scan"

        elif observed == expected.upper():
            status = "PASS"
            message = f"Port matches expected state: {expected}"

        else:
            status = "ALERT"
            message = (
                f"Expected {expected}, but observed {observed}"
            )

        findings.append({
            "port": port,
            "service": service,
            "expected": expected,
            "observed": observed,
            "status": status,
            "message": message
        })

    return findings


def load_policy(policy_path):
    """Load and validate the policy JSON file."""
    with Path(policy_path).open(encoding="utf-8") as file:
        policy = json.load(file)

    if not isinstance(policy.get("expected_ports"), dict):
        raise ValueError("'expected_ports' must be a JSON object")

    allowed_states = {"OPEN", "CLOSED"}

    for port_text, details in policy["expected_ports"].items():
        port = int(port_text)

        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid TCP port: {port}")

        if not isinstance(details, dict):
            raise ValueError(f"Invalid policy entry for port {port}")

        expected = details.get("expected_state", "").upper()

        if expected not in allowed_states:
            raise ValueError(
                f"Invalid expected_state for port {port}: {expected}"
            )

        if not isinstance(details.get("service"), str):
            raise ValueError(f"Missing service name for port {port}")

    return policy
