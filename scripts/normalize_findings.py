#!/usr/bin/env python3

import csv
import json
import sys
from pathlib import Path

DEFAULT_OUTPUT = Path("reports/normalized-findings.json")
GOVERNANCE_REGISTER = Path(
    "reports/risk-register/iam-risk-register.csv"
)


def load_rows(path, delimiter):
    with path.open(
        newline="",
        encoding="utf-8-sig"
    ) as f:
        return list(csv.DictReader(f, delimiter=delimiter))


def normalize(value):
    return (value or "").strip()


def first_category(value):
    categories = [
        item.strip()
        for item in normalize(value).split("|")
        if item.strip()
    ]

    return categories[0] if categories else "unknown"


def governance_key(finding_id, resource_uid):
    return (
        normalize(finding_id),
        normalize(resource_uid)
    )


def build_governance_index(rows):
    index = {}

    for row in rows:
        key = governance_key(
            row.get("finding_id"),
            row.get("resource_uid")
        )

        if not all(key):
            raise ValueError(
                "Governance record has empty finding_id "
                "or resource_uid"
            )

        if key in index:
            raise ValueError(
                "Duplicate governance record: "
                f"{key[0]} | {key[1]}"
            )

        index[key] = row

    return index


def normalize_row(row, governance):
    finding_id = normalize(row.get("CHECK_ID"))
    resource_uid = normalize(row.get("RESOURCE_UID"))

    key = governance_key(finding_id, resource_uid)

    if key not in governance:
        raise ValueError(
            "No governance record for: "
            f"{finding_id} | {resource_uid}"
        )

    decision = governance[key]

    return {
        "finding_id": finding_id,
        "resource_uid": resource_uid,
        "severity": normalize(
            row.get("SEVERITY")
        ).lower(),
        "service": normalize(
            row.get("SERVICE_NAME")
        ),
        "category": first_category(
            row.get("CATEGORIES")
        ),
        "risk": normalize(row.get("RISK")),
        "status": normalize(
            row.get("STATUS")
        ).upper(),
        "owner": normalize(
            decision.get("owner")
        ),
        "disposition": normalize(
            decision.get("disposition")
        ).upper(),
        "lifecycle_status": normalize(
            decision.get("status")
        ).upper(),
        "check_title": normalize(
            row.get("CHECK_TITLE")
        ),
        "resource_type": normalize(
            row.get("RESOURCE_TYPE")
        ),
        "resource_name": normalize(
            row.get("RESOURCE_NAME")
        ),
        "status_extended": normalize(
            row.get("STATUS_EXTENDED")
        ),
        "remediation": normalize(
            row.get(
                "REMEDIATION_RECOMMENDATION_TEXT"
            )
        ),
        "compliance": normalize(
            row.get("COMPLIANCE")
        ),
        "categories": normalize(
            row.get("CATEGORIES")
        )
    }


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python3 scripts/normalize_findings.py "
            "<prowler_csv>"
        )
        return 2

    source = Path(sys.argv[1])

    if not source.exists():
        print(f"ERROR: input file not found: {source}")
        return 2

    if not GOVERNANCE_REGISTER.exists():
        print(
            "ERROR: governance register not found: "
            f"{GOVERNANCE_REGISTER}"
        )
        return 2

    prowler_rows = load_rows(source, ";")
    governance_rows = load_rows(
        GOVERNANCE_REGISTER,
        ","
    )

    governance = build_governance_index(
        governance_rows
    )

    failed_rows = [
        row
        for row in prowler_rows
        if normalize(row.get("STATUS")).upper()
        == "FAIL"
    ]

    findings = [
        normalize_row(row, governance)
        for row in failed_rows
    ]

    DEFAULT_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with DEFAULT_OUTPUT.open(
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            findings,
            f,
            indent=2,
            ensure_ascii=False
        )
        f.write("\n")

    print(
        f"Normalized failed findings: "
        f"{len(findings)}"
    )
    print(
        f"Governance records loaded: "
        f"{len(governance)}"
    )
    print(
        f"Output: {DEFAULT_OUTPUT}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
