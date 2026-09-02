#!/usr/bin/env python3

import csv
import json
import sys
from pathlib import Path

POLICY_PATH = Path("config/risk-policy.json")
NORMALIZED_FINDINGS = Path("reports/normalized-findings.json")


def load_json(path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def load_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def normalize(value):
    return (value or "").strip()


def calculate_score(finding, policy):
    severity = normalize(finding.get("severity")).lower()

    severity_config = policy.get("severity", {}).get(severity)

    if severity_config is None:
        raise ValueError(f"Unknown severity: {severity!r}")

    return severity_config["base_score"]


def evaluate(finding, policy):
    required = policy["decision_model"]["required_fields"]

    missing = [
        field
        for field in required
        if not normalize(finding.get(field))
    ]

    if missing:
        raise ValueError(
            f"Missing required fields: {', '.join(missing)}"
        )

    severity = normalize(finding["severity"]).lower()
    disposition = normalize(finding["disposition"]).upper()
    status = normalize(finding["lifecycle_status"]).upper()

    if severity not in policy["severity"]:
        raise ValueError(f"Unknown severity: {severity}")

    if disposition not in policy["dispositions"]:
        raise ValueError(f"Unknown disposition: {disposition}")

    if status not in policy["lifecycle"]:
        raise ValueError(f"Unknown status: {status}")

    score = calculate_score(finding, policy)

    if disposition == "EXCEPTION":
        decision = "EXCEPTION"
    elif disposition == "REPORT_ONLY":
        decision = "REPORT_ONLY"
    elif disposition == "INVESTIGATE":
        decision = "INVESTIGATE"
    elif severity in ("critical", "high"):
        decision = "BLOCK"
    elif severity == "medium":
        decision = "INVESTIGATE"
    else:
        decision = "REPORT_ONLY"

    return {
        "finding_id": finding["finding_id"],
        "resource_uid": finding["resource_uid"],
        "severity": severity,
        "category": finding["category"],
        "owner": finding["owner"],
        "disposition": disposition,
        "status": status,
        "risk_score": score,
        "decision": decision,
    }


def main():
    if not POLICY_PATH.exists():
        print(f"ERROR: policy not found: {POLICY_PATH}")
        return 2

    if not NORMALIZED_FINDINGS.exists():
        print(
            f"ERROR: normalized findings not found: "
            f"{NORMALIZED_FINDINGS}"
        )
        return 2

    policy = load_json(POLICY_PATH)
    findings = load_json(NORMALIZED_FINDINGS)

    decisions = [
        evaluate(finding, policy)
        for finding in findings
    ]

    counts = {}

    for decision in decisions:
        key = decision["decision"]
        counts[key] = counts.get(key, 0) + 1

    print("RISK ENGINE")
    print("===========")
    print(f"Records evaluated: {len(decisions)}")
    print(f"BLOCK:             {counts.get('BLOCK', 0)}")
    print(f"INVESTIGATE:       {counts.get('INVESTIGATE', 0)}")
    print(f"EXCEPTION:         {counts.get('EXCEPTION', 0)}")
    print(f"REPORT_ONLY:       {counts.get('REPORT_ONLY', 0)}")

    print("\nRisk scores:")

    for decision in sorted(
        decisions,
        key=lambda item: item["risk_score"],
        reverse=True,
    ):
        print(
            f"- {decision['risk_score']:>2} | "
            f"{decision['severity'].upper():<8} | "
            f"{decision['decision']:<11} | "
            f"{decision['finding_id']} | "
            f"{decision['resource_uid']}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
