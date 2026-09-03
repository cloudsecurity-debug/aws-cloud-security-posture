#!/usr/bin/env python3

import csv
import json
import sys
from pathlib import Path

POLICY_PATH = Path("config/risk-policy.json")
NORMALIZED_FINDINGS = Path("reports/normalized-findings.json")
SECURITY_CONTEXT = Path("reports/security-context.json")
REPORT_PATH = Path("reports/risk-decision-report.md")
DECISIONS_PATH = Path("reports/risk-decisions.json")


def load_json(path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def load_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def normalize(value):
    return (value or "").strip()


def context_score(context, policy):
    scoring = policy["context_scoring"]

    dimensions = (
        "asset_criticality",
        "exposure",
        "business_impact",
        "exploitability",
    )

    contributions = {}

    for dimension in dimensions:
        value = (context.get(dimension) or "").strip().upper()

        if value not in scoring[dimension]:
            raise ValueError(
                f"Unknown {dimension}: {value!r}"
            )

        contributions[dimension] = scoring[dimension][value]

    return sum(contributions.values()), contributions


def evaluate(finding, context, policy):
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
    status = normalize(finding["status"]).upper()
    lifecycle_status = normalize(finding["lifecycle_status"]).upper()

    if severity not in policy["severity"]:
        raise ValueError(f"Unknown severity: {severity}")

    if disposition not in policy["dispositions"]:
        raise ValueError(f"Unknown disposition: {disposition}")

    if status not in {"FAIL", "PASS", "MUTED"}:
        raise ValueError(f"Unknown status: {status}")

    if lifecycle_status not in policy["lifecycle"]:
        raise ValueError(
            f"Unknown lifecycle status: {lifecycle_status}"
        )

    base_score = policy["severity"][severity]["base_score"]
    base_action = policy["severity"][severity]["default_action"]

    contextual_score, contributions = context_score(
        context,
        policy,
    )

    total_score = min(
        base_score + contextual_score,
        100,
    )

    threshold = policy["context_scoring"]["block_threshold"]

    if disposition == "EXCEPTION":
        decision = "EXCEPTION"
        rationale = (
            "Explicit governance exception takes precedence "
            "over contextual risk."
        )

    elif disposition == "REPORT_ONLY":
        decision = "REPORT_ONLY"
        rationale = (
            "Explicit REPORT_ONLY governance disposition "
            "keeps the finding non-blocking."
        )

    elif total_score >= threshold:
        decision = "BLOCK"
        rationale = (
            f"Effective risk score {total_score} reaches "
            f"the block threshold of {threshold}."
        )

    else:
        decision = base_action

        if decision == "INVESTIGATE":
            rationale = (
                f"Effective score {total_score} remains below "
                f"the block threshold; evidence requires "
                f"investigation."
            )
        else:
            rationale = (
                f"Effective score {total_score} remains below "
                f"the block threshold and follows the severity "
                f"default action."
            )

    return {
        "finding_id": finding["finding_id"],
        "resource_uid": finding["resource_uid"],
        "severity": severity,
        "category": finding["category"],
        "owner": finding["owner"],
        "disposition": disposition,
        "status": status,
        "lifecycle_status": lifecycle_status,
        "base_score": base_score,
        "context_score": contextual_score,
        "risk_score": total_score,
        "decision": decision,
        "rationale": rationale,
        "context_contributions": contributions,
        "context": context,
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

    if not SECURITY_CONTEXT.exists():
        print(
            f"ERROR: security context not found: "
            f"{SECURITY_CONTEXT}"
        )
        return 2

    policy = load_json(POLICY_PATH)
    findings = load_json(NORMALIZED_FINDINGS)
    contexts = load_json(SECURITY_CONTEXT)

    context_index = {
        item["resource_uid"]: item
        for item in contexts
    }

    decisions = []

    for finding in findings:
        context = context_index.get(
            finding["resource_uid"],
            {
                "resource_uid": finding["resource_uid"],
                "asset_criticality": "UNKNOWN",
                "exposure": "UNKNOWN",
                "business_impact": "UNKNOWN",
                "exploitability": "UNKNOWN",
                "compensating_controls": [],
                "remediation_risk": "UNKNOWN",
                "exception_status": "UNKNOWN",
                "evidence": []
            }
        )

        decision = evaluate(finding, context, policy)
        decisions.append(decision)

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

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    DECISIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DECISIONS_PATH.open("w", encoding="utf-8") as decisions_file:
        json.dump(decisions, decisions_file, indent=2)
        decisions_file.write("\n")

    with REPORT_PATH.open("w", encoding="utf-8") as report:
        report.write("# CSPM Risk Decision Report\n\n")
        report.write(f"- Findings evaluated: {len(decisions)}\n")
        report.write(f"- BLOCK: {counts.get('BLOCK', 0)}\n")
        report.write(f"- INVESTIGATE: {counts.get('INVESTIGATE', 0)}\n")
        report.write(f"- EXCEPTION: {counts.get('EXCEPTION', 0)}\n")
        report.write(f"- REPORT_ONLY: {counts.get('REPORT_ONLY', 0)}\n")
        report.write(
            f"- Result: **{'BLOCK' if counts.get('BLOCK', 0) else 'PASS'}**\n\n"
        )

        report.write(
            "| Score | Base | Context | Severity | Decision | Disposition | Owner | Finding | Resource |\n"
        )
        report.write(
            "|---:|---:|---:|---|---|---|---|---|---|\n"
        )

        for decision in sorted(
            decisions,
            key=lambda item: item["risk_score"],
            reverse=True,
        ):
            report.write(
                f"| {decision['risk_score']} | "
                f"{decision['base_score']} | "
                f"{decision['context_score']} | "
                f"{decision['severity'].upper()} | "
                f"{decision['decision']} | "
                f"{decision['disposition']} | "
                f"{decision['owner']} | "
                f"`{decision['finding_id']}` | "
                f"`{decision['resource_uid']}` |\n"
            )

        report.write("\n## Decision Rationale\n\n")

        for decision in sorted(
            decisions,
            key=lambda item: item["risk_score"],
            reverse=True,
        ):
            report.write(
                f"### `{decision['finding_id']}` — {decision['decision']}\n\n"
            )
            report.write(
                f"- **Resource:** `{decision['resource_uid']}`\n"
            )
            report.write(
                f"- **Severity:** {decision['severity'].upper()}\n"
            )
            report.write(
                f"- **Base score:** {decision['base_score']}\n"
            )
            report.write(
                f"- **Context score:** {decision['context_score']}\n"
            )

            contributions = decision["context_contributions"]
            report.write("- **Context contributions:** ")
            report.write(
                ", ".join(
                    f"{dimension}={value:+d}"
                    for dimension, value in contributions.items()
                )
            )
            report.write("\n")

            report.write(
                f"- **Disposition:** {decision['disposition']}\n"
            )
            report.write(
                f"- **Lifecycle:** {decision['lifecycle_status']}\n"
            )
            report.write(
                f"- **Rationale:** {decision['rationale']}\n\n"
            )

    print(f"\nReport: {REPORT_PATH}")
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
