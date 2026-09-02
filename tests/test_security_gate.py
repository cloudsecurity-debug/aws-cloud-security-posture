import json
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GATE = PROJECT_ROOT / "scripts" / "security_gate.py"


def write_policy(path):
    policy = {
        "version": 1,
        "default_action": "BLOCK",
        "rules": {
            "critical": "BLOCK",
            "high": "BLOCK",
            "medium": "INVESTIGATE",
            "low": "REPORT_ONLY",
        },
        "exceptions": [
            {
                "finding_id": "iam_test_exception",
                "resource_name": "project1-role",
                "action": "EXCEPTION",
                "reason": "Approved Project 1 boundary",
            }
        ],
    }
    path.write_text(json.dumps(policy), encoding="utf-8")


def write_csv(path, rows):
    headers = [
        "STATUS",
        "CHECK_ID",
        "SEVERITY",
        "RESOURCE_NAME",
    ]

    lines = [";".join(headers)]

    for row in rows:
        lines.append(";".join(row))

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_gate(csv_path, policy_path, report_path):
    command = [
        sys.executable,
        str(GATE),
        str(csv_path),
        str(policy_path),
        str(report_path),
    ]

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    return result


def test_high_finding_blocks():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        write_policy(tmp / "policy.json")

        rows = [
            ("FAIL", "iam_test_high", "high", "test-admin"),
        ]

        csv_path = tmp / "findings.csv"
        write_csv(csv_path, rows)

        # Use the repository policy for this test.
        result = run_gate(csv_path, tmp / "policy.json", tmp / "report.md")

        assert result.returncode == 1
        assert "RESULT: BLOCK" in result.stdout


def test_exception_does_not_block():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        write_policy(tmp / "policy.json")

        rows = [
            (
                "FAIL",
                "iam_test_exception",
                "high",
                "project1-role",
            ),
        ]

        csv_path = tmp / "findings.csv"
        write_csv(csv_path, rows)

        result = run_gate(csv_path, tmp / "policy.json", tmp / "report.md")

        assert result.returncode == 0
        assert "RESULT: PASS" in result.stdout


def test_pass_finding_is_ignored():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        write_policy(tmp / "policy.json")

        rows = [
            ("PASS", "iam_test_high", "high", "test-admin"),
        ]

        csv_path = tmp / "findings.csv"
        write_csv(csv_path, rows)

        result = run_gate(csv_path, tmp / "policy.json", tmp / "report.md")

        assert result.returncode == 0
        assert "RESULT: PASS" in result.stdout


if __name__ == "__main__":
    test_high_finding_blocks()
    test_exception_does_not_block()
    test_pass_finding_is_ignored()
    print("SECURITY GATE TESTS: PASS")
