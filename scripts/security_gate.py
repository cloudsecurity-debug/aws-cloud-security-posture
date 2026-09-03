#!/usr/bin/env python3

import json
import sys
from pathlib import Path

DECISIONS_PATH = Path("reports/risk-decisions.json")
REPORT_PATH = Path("reports/security-gate-report.md")

VALID_DECISIONS = {
    "BLOCK",
    "INVESTIGATE",
    "EXCEPTION",
    "REPORT_ONLY",
}

REQUIRED_FIELDS = {
    "finding_id",
    "resource_uid",
    "severity",
    "decision",
    "disposition",
    "owner",
    "status",
    "lifecycle_status",
}


def load_decisions(path):
    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Risk decisions must be a JSON array")

    return data


def validate_decision(decision):
    if not isinstance(decision, dict):
        raise ValueError("Each risk decision must be an object")

    missing = REQUIRED_FIELDS - decision.keys()
    if missing:
        raise ValueError(
            "Missing required fields: "
            + ", ".join(sorted(missing))
        )

    action = decision["decision"]

    if action not in VALID_DECISIONS:
        raise ValueError(f"Unknown risk decision: {action}")

    if decision["status"] not in {"FAIL", "PASS", "MUTED"}:
        raise ValueError(
            f"Unknown finding status: {decision['status']}"
        )

    if decision["lifecycle_status"] not in {
        "OPEN",
        "IN_PROGRESS",
        "VALIDATING",
        "CLOSED",
    }:
        raise ValueError(
            f"Unknown lifecycle status: "
            f"{decision['lifecycle_status']}"
        )


def main():
    decisions_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else DECISIONS_PATH
    )
    report_path = (
        Path(sys.argv[2])
        if len(sys.argv) > 2
        else REPORT_PATH
    )

    if not decisions_path.exists():
        print(f"ERROR: risk decisions not found: {decisions_path}")
        return 2

    try:
        decisions = load_decisions(decisions_path)

        for decision in decisions:
            validate_decision(decision)

    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: invalid risk decision contract: {exc}")
        return 2

    blocks = [
        d for d in decisions
        if d["decision"] == "BLOCK"
    ]
    investigates = [
        d for d in decisions
        if d["decision"] == "INVESTIGATE"
    ]
    exceptions = [
        d for d in decisions
        if d["decision"] == "EXCEPTION"
    ]
    report_only = [
        d for d in decisions
        if d["decision"] == "REPORT_ONLY"
    ]

    print("CSPM SECURITY GATE")
    print("==================")
    print(f"Decisions evaluated: {len(decisions)}")
    print(f"BLOCK:               {len(blocks)}")
    print(f"INVESTIGATE:         {len(investigates)}")
    print(f"EXCEPTION:           {len(exceptions)}")
    print(f"REPORT_ONLY:         {len(report_only)}")

    if blocks:
        print("\nBlocking decisions:")
        for item in blocks:
            print(
                f"- {item['severity'].upper()} | "
                f"{item['finding_id']} | "
                f"{item['resource_uid']}"
            )

    if investigates:
        print("\nInvestigation required:")
        for item in investigates:
            print(
                f"- {item['severity'].upper()} | "
                f"{item['finding_id']} | "
                f"{item['resource_uid']}"
            )

    if exceptions:
        print("\nAccepted exceptions:")
        for item in exceptions:
            print(
                f"- {item['finding_id']} | "
                f"{item['resource_uid']}"
            )

    result = "BLOCK" if blocks else "PASS"

    report_path.parent.mkdir(parents=True, exist_ok=True)

    with report_path.open("w", encoding="utf-8") as report:
        report.write("# CSPM Security Gate Report\n\n")
        report.write(
            f"- Decisions evaluated: {len(decisions)}\n"
        )
        report.write(f"- BLOCK: {len(blocks)}\n")
        report.write(
            f"- INVESTIGATE: {len(investigates)}\n"
        )
        report.write(f"- EXCEPTION: {len(exceptions)}\n")
        report.write(f"- REPORT_ONLY: {len(report_only)}\n")
        report.write(f"- Result: **{result}**\n\n")

        if blocks:
            report.write("## Blocking Decisions\n\n")
            report.write(
                "| Severity | Finding | Resource | "
                "Disposition | Owner |\n"
            )
            report.write(
                "|---|---|---|---|---|\n"
            )

            for item in blocks:
                report.write(
                    f"| {item['severity'].upper()} | "
                    f"`{item['finding_id']}` | "
                    f"`{item['resource_uid']}` | "
                    f"{item['disposition']} | "
                    f"{item['owner']} |\n"
                )

        if investigates:
            report.write(
                "\n## Investigation Required\n\n"
            )

            for item in investigates:
                report.write(
                    f"- `{item['finding_id']}` on "
                    f"`{item['resource_uid']}` — "
                    f"{item['rationale']}\n"
                )

        if exceptions:
            report.write(
                "\n## Accepted Exceptions\n\n"
            )

            for item in exceptions:
                report.write(
                    f"- `{item['finding_id']}` on "
                    f"`{item['resource_uid']}`\n"
                )

    print(f"\nRESULT: {result}")
    print(f"Report: {report_path}")

    return 1 if blocks else 0


if __name__ == "__main__":
    sys.exit(main())
