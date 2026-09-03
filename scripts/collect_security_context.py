#!/usr/bin/env python3

import json
import subprocess
import sys
from pathlib import Path

FINDINGS = Path("reports/normalized-findings.json")
REGISTRY = Path("config/security-context-registry.json")
OUTPUT = Path("reports/security-context.json")


def aws(*args):
    result = subprocess.run(
        ["aws", *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def s3_context(resource_uid):
    try:
        config = aws(
            "s3api",
            "get-public-access-block",
            "--bucket",
            resource_uid,
        )
    except Exception:
        return None

    required = {
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    }

    if required.issubset(config) and all(config[key] is True for key in required):
        return {
            "exposure": "PRIVATE",
            "evidence": [
                {
                    "source": "aws:s3api:get-public-access-block",
                    "fact": "All four S3 Public Access Block controls are enabled."
                }
            ],
        }

    return {
        "exposure": "UNKNOWN",
        "evidence": [
            {
                "source": "aws:s3api:get-public-access-block",
                "fact": "S3 Public Access Block configuration is not fully enabled."
            }
        ],
    }


def main():
    if not FINDINGS.exists():
        print(f"ERROR: {FINDINGS} not found")
        return 2

    if not REGISTRY.exists():
        print(f"ERROR: {REGISTRY} not found")
        return 2

    findings = json.loads(FINDINGS.read_text(encoding="utf-8"))
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))

    registry_index = {
        item["resource_uid"]: item
        for item in registry
    }

    contexts = []

    for finding in findings:
        resource_uid = finding["resource_uid"]

        context = registry_index.get(
            resource_uid,
            {
                "resource_uid": resource_uid,
                "asset_criticality": "UNKNOWN",
                "exposure": "UNKNOWN",
                "business_impact": "UNKNOWN",
                "exploitability": "UNKNOWN",
                "compensating_controls": [],
                "remediation_risk": "UNKNOWN",
                "exception_status": "UNKNOWN",
                "evidence": [],
            },
        )

        context = dict(context)
        context["resource_uid"] = resource_uid
        context["evidence"] = list(context.get("evidence", []))

        if finding["service"].lower() == "s3":
            live_s3 = s3_context(resource_uid)

            if live_s3:
                context["exposure"] = live_s3["exposure"]
                context["evidence"].extend(live_s3["evidence"])

        context["evidence"].append(
            {
                "source": "prowler",
                "fact": (
                    f"{finding['finding_id']} failed with "
                    f"severity {finding['severity']}"
                ),
            }
        )

        contexts.append(context)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(contexts, indent=2),
        encoding="utf-8",
    )

    print(f"Security contexts generated: {len(contexts)}")
    print(f"Registry entries used: {sum(1 for f in findings if f['resource_uid'] in registry_index)}")
    print(f"Output: {OUTPUT}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
