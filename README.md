# AWS Cloud Security Posture

A policy-driven AWS Cloud Security Posture Management (CSPM) project demonstrating how cloud-security findings can be assessed, classified, documented, and enforced through CI/CD.

## Project Objective

This project builds a repeatable AWS IAM security assessment pipeline using Prowler, policy-as-code, automated testing, and CI/CD enforcement.

- Assess AWS IAM security posture with Prowler.
- Preserve security assessment evidence.
- Classify findings using a version-controlled policy.
- Enforce BLOCK, INVESTIGATE, EXCEPTION, and REPORT_ONLY decisions.
- Generate a security-gate report.
- Fail CI when blocking findings are present.

## Security Gate Policy

| Severity | Action |
|---|---|
| Critical | BLOCK |
| High | BLOCK |
| Medium | INVESTIGATE |
| Low | REPORT_ONLY |

## Latest Assessment

The latest local IAM assessment evaluated 16 failed findings:

- 8 BLOCK
- 2 INVESTIGATE
- 2 EXCEPTION
- 4 REPORT_ONLY

Result: BLOCK

The BLOCK result is intentional. The gate enforces policy rather than modifying administrator access simply to make the scan pass.

## CI/CD

GitHub Actions authenticates to AWS through OIDC and runs the IAM-focused Prowler assessment. The resulting findings are evaluated by the security gate and both Prowler evidence and the gate report are preserved as CI artifacts.

## Testing

Tests are located in `tests/test_security_gate.py`.

Run:

```bash
python3 tests/test_security_gate.py
```

Expected result:

```text
SECURITY GATE TESTS: PASS
```

## Security Engineering Principles

- Policy as code
- Explicit, resource-scoped exceptions
- Evidence preservation
- Fail-closed enforcement
- Separation of assessment and remediation

## Project Scope

This project focuses on AWS IAM posture assessment, CSPM, policy enforcement, CI/CD integration, evidence preservation, finding classification, and security reporting.

Automatic administrator-access remediation is outside the current scope.

## Portfolio Outcome

This project demonstrates the complete security-engineering control chain:

AWS → Prowler → Findings → Policy → Classification → Security Gate → CI Enforcement → Evidence
