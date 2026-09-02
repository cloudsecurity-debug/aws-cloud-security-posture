# Assessment Access Design

## Objective

Provide Project 2 with read-only AWS security visibility for CSPM assessment without granting remediation permissions.

## Candidate Policy

AWS-managed policy:

`SecurityAudit`

ARN:

`arn:aws:iam::aws:policy/SecurityAudit`

Observed default policy version:

`v92`

Observed update date:

`2026-08-17T15:27:26+00:00`

## Design Decision

Use `SecurityAudit` as the initial assessment permission baseline rather than recreating a large collection of security-read permissions manually.

The policy is intended for security assessment and audit visibility and is currently not attached to any IAM user, group, or role in this account.

## Separation of Duties

Assessment access must remain separate from remediation access.

The assessment role must not receive:

- general write permissions,
- resource deletion permissions,
- IAM privilege-management permissions,
- Project 1 remediation permissions.

## Project 1 Boundary

These existing Project 1 roles remain outside Project 2:

- `cloud-security-autoremediation-config`
- `cloud-security-autoremediation-remediation-lambda`

Project 2 will not modify their permissions.

## Proposed Architecture

```text
Human administrative identity
        |
        | AssumeRole
        v
Project2-SecurityAssessmentRole
        |
        +-- AWS managed SecurityAudit
        |
        +-- Read-only assessment
        |
        +-- No remediation permissions
