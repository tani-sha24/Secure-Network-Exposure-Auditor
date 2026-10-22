
import csv
import json
import tempfile
import unittest
from pathlib import Path

from src.report_generator import (
    build_report,
    write_csv_report,
    write_json_report,
)


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.findings = [
            {
                "port": 22,
                "service": "SSH",
                "expected": "CLOSED",
                "observed": "CLOSED",
                "status": "PASS",
                "message": "Port matches expected state: CLOSED",
            },
            {
                "port": 631,
                "service": "IPP/CUPS",
                "expected": "CLOSED",
                "observed": "OPEN",
                "status": "ALERT",
                "message": "Expected CLOSED, but observed OPEN",
            },
        ]
        self.report = build_report(
            "127.0.0.1", "Test policy", self.findings
        )
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.output_dir = Path(self.temp_dir.name)

    def test_summary_counts(self):
        summary = self.report["summary"]
        self.assertEqual(summary["ports_checked"], 2)
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["alerts"], 1)
        self.assertEqual(summary["inconclusive"], 0)

    def test_json_report(self):
        path = write_json_report(
            self.report, self.output_dir / "report.json"
        )
        with path.open(encoding="utf-8") as file:
            loaded = json.load(file)

        self.assertEqual(loaded["target"], "127.0.0.1")
        self.assertEqual(loaded["summary"]["alerts"], 1)

    def test_csv_report(self):
        path = write_csv_report(
            self.report, self.output_dir / "report.csv"
        )
        with path.open(encoding="utf-8", newline="") as file:
            rows = list(csv.DictReader(file))

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["port"], "631")
        self.assertEqual(rows[1]["status"], "ALERT")


if __name__ == "__main__":
    unittest.main()
