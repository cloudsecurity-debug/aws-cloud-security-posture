# Project 2 Operating Model

## Purpose

Project 2 is an AWS Cloud Security Posture Management (CSPM) program.

Its purpose is to assess AWS security posture, prioritize findings, remediate approved issues, verify remediation, preserve evidence, and enforce security gates in CI/CD.

## Primary Tooling

- Prowler — AWS security posture assessment
- AWS CLI — controlled investigation and remediation
- Terraform — infrastructure as code
- GitHub Actions — CI/CD security gates
- Python — supporting automation and tests
- Git — change and evidence history

## Assessment Workflow

1. Run Prowler against the target AWS environment.
2. Preserve the assessment output.
3. Normalize relevant findings into the project risk register.
4. Investigate affected resources and access paths.
5. Assign severity, impact, owner, disposition, and status.
6. Remediate only approved findings.
7. Re-run Prowler.
8. Compare baseline and post-remediation results.
9. Verify the AWS control directly where appropriate.
10. Store evidence supporting the result.

## Remediation Classes

### AUTO_REMEDIATE

Safe, deterministic changes with a clearly defined scope and rollback path.

### MANUAL_REMEDIATE

Changes requiring human validation because they can affect authentication, authorization, availability, or business access.

### INVESTIGATE

Findings requiring additional evidence before deciding whether remediation is appropriate.

### EXCEPTION

A finding intentionally accepted for a documented reason, with an owner and review/expiration date.

### REPORT_ONLY

A finding that is informational, contextual, or not independently sufficient to establish a vulnerability.

## Project 1 Boundary

The following Project 1 IAM roles are explicitly outside Project 2 remediation scope:

- `cloud-security-autoremediation-config`
- `cloud-security-autoremediation-remediation-lambda`

Project 2 must not modify their permissions.

## IAM Migration Principle

The current human administrator access path must not be removed until a replacement access path has been:

1. designed,
2. created,
3. validated,
4. tested for required operations,
5. given a recovery path.

The current `AdministratorAccess` dependency therefore remains unchanged during the design phase.

## Required Evidence

Every material remediation should produce evidence showing:

- finding before remediation,
- affected resource,
- intended control,
- change performed,
- direct AWS verification,
- Prowler result after remediation,
- final disposition.

## CI/CD Security Gate

The final project should support an automated security gate that can fail when defined unacceptable findings are introduced.

The gate must distinguish:

- findings that block deployment,
- findings that require investigation,
- accepted exceptions,
- report-only findings.

## Design Principle

The project should demonstrate security engineering judgment rather than simply maximizing the scanner score.

A finding should be remediated because the risk warrants remediation, not merely because a scanner reports it.
