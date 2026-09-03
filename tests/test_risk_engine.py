import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json

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


def context(**overrides):
    base = {
        "resource_uid": "arn:aws:iam::123456789012:user/test-user",
        "asset_criticality": "UNKNOWN",
        "exposure": "UNKNOWN",
        "business_impact": "UNKNOWN",
        "exploitability": "UNKNOWN",
        "compensating_controls": [],
        "remediation_risk": "UNKNOWN",
        "exception_status": "NONE",
        "evidence": [],
    }
    base.update(overrides)
    return base


def test_high_manual_remediation_blocks():
    result = evaluate(
        finding(),
        context(),
        load_policy(),
    )

    assert result["decision"] == "BLOCK"
    assert result["base_score"] == 30
    assert result["context_score"] == 0
    assert result["risk_score"] == 30


def test_critical_finding_blocks():
    result = evaluate(
        finding(
            severity="critical",
            disposition="MANUAL_REMEDIATE",
        ),
        context(),
        load_policy(),
    )

    assert result["decision"] == "BLOCK"
    assert result["base_score"] == 40
    assert result["context_score"] == 0
    assert result["risk_score"] == 40


def test_context_escalates_medium_finding():
    result = evaluate(
        finding(
            severity="medium",
            disposition="MANUAL_REMEDIATE",
        ),
        context(
            asset_criticality="CRITICAL",
            exposure="INTERNET",
            business_impact="CRITICAL",
            exploitability="HIGH",
        ),
        load_policy(),
    )

    assert result["base_score"] == 20
    assert result["context_score"] == 45
    assert result["risk_score"] == 65
    assert result["decision"] == "BLOCK"

    assert result["context_contributions"] == {
        "asset_criticality": 10,
        "exposure": 15,
        "business_impact": 10,
        "exploitability": 10,
    }


def test_unknown_context_contributes_zero():
    result = evaluate(
        finding(
            severity="medium",
            disposition="INVESTIGATE",
        ),
        context(),
        load_policy(),
    )

    assert result["context_score"] == 0
    assert result["risk_score"] == 20
    assert result["decision"] == "INVESTIGATE"


def test_exception_takes_precedence_over_context():
    result = evaluate(
        finding(
            severity="high",
            disposition="EXCEPTION",
        ),
        context(
            asset_criticality="CRITICAL",
            exposure="INTERNET",
            business_impact="CRITICAL",
            exploitability="HIGH",
        ),
        load_policy(),
    )

    assert result["decision"] == "EXCEPTION"
    assert result["risk_score"] == 75


def test_report_only_takes_precedence_over_context():
    result = evaluate(
        finding(
            severity="low",
            disposition="REPORT_ONLY",
        ),
        context(
            asset_criticality="CRITICAL",
            exposure="INTERNET",
            business_impact="CRITICAL",
            exploitability="HIGH",
        ),
        load_policy(),
    )

    assert result["decision"] == "REPORT_ONLY"
    assert result["risk_score"] == 55


def test_missing_required_field_fails_closed():
    item = finding()
    del item["owner"]

    try:
        evaluate(item, context(), load_policy())
    except ValueError as exc:
        assert "Missing required fields: owner" in str(exc)
    else:
        raise AssertionError("Missing required field was accepted")


def test_unknown_severity_fails_closed():
    try:
        evaluate(
            finding(severity="extreme"),
            context(),
            load_policy(),
        )
    except ValueError as exc:
        assert "Unknown severity" in str(exc)
    else:
        raise AssertionError("Unknown severity was accepted")


def test_unknown_lifecycle_status_fails_closed():
    try:
        evaluate(
            finding(lifecycle_status="UNKNOWN"),
            context(),
            load_policy(),
        )
    except ValueError as exc:
        assert "Unknown lifecycle status" in str(exc)
    else:
        raise AssertionError("Unknown lifecycle status was accepted")


def test_unknown_context_value_fails_closed():
    try:
        evaluate(
            finding(),
            context(asset_criticality="EXTREME"),
            load_policy(),
        )
    except ValueError as exc:
        assert "Unknown asset_criticality" in str(exc)
    else:
        raise AssertionError("Unknown context value was accepted")
