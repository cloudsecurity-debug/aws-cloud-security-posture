import json
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GATE = PROJECT_ROOT / "scripts" / "security_gate.py"


def write_decisions(path, decisions):
    path.write_text(
        json.dumps(decisions, indent=2),
        encoding="utf-8",
    )


def base_decision(**overrides):
    decision = {
        "finding_id": "iam_test_finding",
        "resource_uid": "test-resource",
        "severity": "high",
        "category": "identity-access",
        "owner": "IAM",
        "disposition": "MANUAL_REMEDIATE",
        "status": "FAIL",
        "lifecycle_status": "OPEN",
        "base_score": 30,
        "context_score": 0,
        "risk_score": 30,
        "decision": "BLOCK",
        "rationale": "Test risk decision",
        "context_contributions": {},
        "context": {},
    }
    decision.update(overrides)
    return decision


def run_gate(decisions_path, report_path, baseline_findings=None):
    baseline_path = decisions_path.parent / "baseline.json"

    baseline_path.write_text(
        json.dumps(
            {
                "version": 1,
                "enforcement": "new_block_findings_only",
                "findings": baseline_findings or [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    command = [
        sys.executable,
        str(GATE),
        str(decisions_path),
        str(baseline_path),
        str(report_path),
    ]

    return subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )


def test_block_decision_fails_gate():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        decisions_path = tmp / "risk-decisions.json"
        report_path = tmp / "report.md"

        write_decisions(
            decisions_path,
            [base_decision()],
        )

        result = run_gate(decisions_path, report_path)

        assert result.returncode == 1
        assert "RESULT: BLOCK" in result.stdout


def test_exception_does_not_block():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        decisions_path = tmp / "risk-decisions.json"
        report_path = tmp / "report.md"

        write_decisions(
            decisions_path,
            [
                base_decision(
                    decision="EXCEPTION",
                    disposition="EXCEPTION",
                )
            ],
        )

        result = run_gate(decisions_path, report_path)

        assert result.returncode == 0
        assert "RESULT: PASS" in result.stdout


def test_report_only_does_not_block():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        decisions_path = tmp / "risk-decisions.json"
        report_path = tmp / "report.md"

        write_decisions(
            decisions_path,
            [
                base_decision(
                    severity="low",
                    disposition="REPORT_ONLY",
                    decision="REPORT_ONLY",
                )
            ],
        )

        result = run_gate(decisions_path, report_path)

        assert result.returncode == 0
        assert "RESULT: PASS" in result.stdout


def test_investigate_does_not_block():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        decisions_path = tmp / "risk-decisions.json"
        report_path = tmp / "report.md"

        write_decisions(
            decisions_path,
            [
                base_decision(
                    severity="medium",
                    disposition="INVESTIGATE",
                    decision="INVESTIGATE",
                )
            ],
        )

        result = run_gate(decisions_path, report_path)

        assert result.returncode == 0
        assert "RESULT: PASS" in result.stdout


def test_unknown_decision_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        decisions_path = tmp / "risk-decisions.json"
        report_path = tmp / "report.md"

        write_decisions(
            decisions_path,
            [
                base_decision(
                    decision="UNKNOWN_DECISION",
                )
            ],
        )

        result = run_gate(decisions_path, report_path)

        assert result.returncode == 2
        assert "invalid security gate contract" in result.stdout


def test_missing_required_field_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        decisions_path = tmp / "risk-decisions.json"
        report_path = tmp / "report.md"

        decision = base_decision()
        del decision["owner"]

        write_decisions(
            decisions_path,
            [decision],
        )

        result = run_gate(decisions_path, report_path)

        assert result.returncode == 2
        assert "Missing required fields: owner" in result.stdout


if __name__ == "__main__":
    test_block_decision_fails_gate()
    test_exception_does_not_block()
    test_report_only_does_not_block()
    test_investigate_does_not_block()
    test_unknown_decision_fails_closed()
    test_missing_required_field_fails_closed()
    print("SECURITY GATE TESTS: PASS")
