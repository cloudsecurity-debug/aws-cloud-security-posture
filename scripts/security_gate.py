#!/usr/bin/env python3

import csv
import json
import sys
from pathlib import Path

POLICY_PATH = Path("config/security-gate-policy.json")
DEFAULT_CSV = Path("reports/post-remediation/iam-post-remediation.csv")


def load_policy():
    with POLICY_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def load_findings(csv_path):
    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f, delimiter=";"))


def evaluate(finding, policy):
    if (finding.get("STATUS") or "").upper() != "FAIL":
        return None

    finding_id = finding.get("CHECK_ID") or ""
    severity = (finding.get("SEVERITY") or "").lower()
    resource_name = finding.get("RESOURCE_NAME") or ""

    for exception in policy.get("exceptions", []):
        if (
            exception.get("finding_id") == finding_id
            and exception.get("resource_name") == resource_name
        ):
            return {
                "action": "EXCEPTION",
                "finding_id": finding_id,
                "severity": severity,
                "resource_name": resource_name,
                "reason": exception.get("reason", ""),
            }

    action = policy.get("rules", {}).get(
        severity,
        policy.get("default_action", "BLOCK"),
    )

    return {
        "action": action,
        "finding_id": finding_id,
        "severity": severity,
        "resource_name": resource_name,
        "reason": "",
    }


def main():
    csv_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CSV

    if not POLICY_PATH.exists():
        print(f"ERROR: policy not found: {POLICY_PATH}")
        return 2

    if not csv_path.exists():
        print(f"ERROR: findings file not found: {csv_path}")
        return 2

    policy = load_policy()
    findings = load_findings(csv_path)

    decisions = [
        decision
        for finding in findings
        if (decision := evaluate(finding, policy)) is not None
    ]

    blocks = [d for d in decisions if d["action"] == "BLOCK"]
    investigates = [d for d in decisions if d["action"] == "INVESTIGATE"]
    exceptions = [d for d in decisions if d["action"] == "EXCEPTION"]
    report_only = [d for d in decisions if d["action"] == "REPORT_ONLY"]

    print("CSPM SECURITY GATE")
    print("==================")
    print(f"Failed findings: {len(decisions)}")
    print(f"BLOCK:           {len(blocks)}")
    print(f"INVESTIGATE:     {len(investigates)}")
    print(f"EXCEPTION:       {len(exceptions)}")
    print(f"REPORT_ONLY:     {len(report_only)}")

    if blocks:
        print("\nBlocking findings:")
        for item in blocks:
            print(
                f"- {item['severity'].upper()} | "
                f"{item['finding_id']} | "
                f"{item['resource_name']}"
            )

    if exceptions:
        print("\nAccepted exceptions:")
        for item in exceptions:
            print(
                f"- {item['finding_id']} | "
                f"{item['resource_name']} | "
                f"{item['reason']}"
            )

    if blocks:
        print("\nRESULT: BLOCK")
        return 1

    print("\nRESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
