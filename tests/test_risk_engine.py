import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import csv
import json
import tempfile
from pathlib import Path

from scripts.risk_engine import evaluate


def load_policy():
    path = Path("config/risk-policy.json")
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def finding(**overrides):
    base = {
        "finding_id": "test-finding",
        "resource_uid": "arn:aws:iam::123456789012:user/test-user",
        "severity": "high",
        "category": "identity-access",
        "owner": "IAM",
        "disposition": "MANUAL_REMEDIATE",
        "lifecycle_status": "OPEN",
        "status": "FAIL",
    }
    base.update(overrides)
    return base


def test_high_manual_remediation_blocks():
    result = evaluate(finding(), load_policy())

    assert result["decision"] == "BLOCK"
    assert result["risk_score"] == 30


def test_critical_finding_blocks():
    result = evaluate(
        finding(
            severity="critical",
            disposition="MANUAL_REMEDIATE",
        ),
        load_policy(),
    )

    assert result["decision"] == "BLOCK"
    assert result["risk_score"] == 40


def test_exception_does_not_block():
    result = evaluate(
        finding(
            severity="high",
            disposition="EXCEPTION",
        ),
        load_policy(),
    )

    assert result["decision"] == "EXCEPTION"


def test_investigation_is_not_block():
    result = evaluate(
        finding(
            severity="medium",
            disposition="INVESTIGATE",
        ),
        load_policy(),
    )

    assert result["decision"] == "INVESTIGATE"
    assert result["risk_score"] == 20


def test_report_only_is_not_block():
    result = evaluate(
        finding(
            severity="low",
            disposition="REPORT_ONLY",
        ),
        load_policy(),
    )

    assert result["decision"] == "REPORT_ONLY"
    assert result["risk_score"] == 10


def test_missing_required_field_fails_closed():
    item = finding()
    del item["owner"]

    try:
        evaluate(item, load_policy())
    except ValueError as exc:
        assert "Missing required fields: owner" in str(exc)
    else:
        raise AssertionError("Missing required field was accepted")


def test_unknown_severity_fails_closed():
    try:
        evaluate(
            finding(severity="extreme"),
            load_policy(),
        )
    except ValueError as exc:
        assert "Unknown severity" in str(exc)
    else:
        raise AssertionError("Unknown severity was accepted")


def test_unknown_status_fails_closed():
    try:
        evaluate(
            finding(lifecycle_status="UNKNOWN"),
            load_policy(),
        )
    except ValueError as exc:
        assert "Unknown status" in str(exc)
    else:
        raise AssertionError("Unknown status was accepted")


if __name__ == "__main__":
    tests = [
        test_high_manual_remediation_blocks,
        test_critical_finding_blocks,
        test_exception_does_not_block,
        test_investigation_is_not_block,
        test_report_only_is_not_block,
        test_missing_required_field_fails_closed,
        test_unknown_severity_fails_closed,
        test_unknown_status_fails_closed,
    ]

    for test in tests:
        test()

    print("RISK ENGINE TESTS: PASS")
