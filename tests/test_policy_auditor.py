import unittest

from src.policy_auditor import audit_results


class TestPolicyAuditor(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "expected_ports": {
                "22": {
                    "service": "SSH",
                    "expected_state": "closed"
                },
                "631": {
                    "service": "IPP/CUPS",
                    "expected_state": "closed"
                }
            }
        }

    def test_expected_closed_port_passes(self):
        results = {22: "CLOSED", 631: "CLOSED"}
        findings = audit_results(results, self.policy)

        self.assertEqual(findings[0]["status"], "PASS")

    def test_unexpected_open_port_alerts(self):
        results = {22: "CLOSED", 631: "OPEN"}
        findings = audit_results(results, self.policy)

        self.assertEqual(findings[1]["status"], "ALERT")
        self.assertIn("Expected CLOSED", findings[1]["message"])

    def test_unscanned_port_is_inconclusive(self):
        results = {22: "CLOSED"}
        findings = audit_results(results, self.policy)

        self.assertEqual(findings[1]["status"], "INCONCLUSIVE")

    def test_no_response_is_inconclusive(self):
        results = {
            22: "CLOSED",
            631: "NO RESPONSE / TIMEOUT"
        }
        findings = audit_results(results, self.policy)

        self.assertEqual(findings[1]["status"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
