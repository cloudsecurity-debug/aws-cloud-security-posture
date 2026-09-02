# IAM Administrator Access Path

## Identity

User:

`cloud-security-admin`

## Direct Permissions

The user has one directly attached AWS-managed policy:

`IAMUserChangePassword`

The user has no inline policies.

## Group Membership

The user is a member of:

`cloud-security-admins1`

## Group Permission

The group has one attached AWS-managed policy:

`AdministratorAccess`

The verified policy document grants:

- `Action: *`
- `Resource: *`

Therefore the user's effective administrative privilege is inherited through the group.

## Credential Dependency

The user has one active IAM access key.

The key is actively used by the current CloudShell/API workflow.

The most recent observed use during this assessment was:

- Service: IAM
- Region: `us-east-1`
- Last used: 2026-09-02T06:13:00+00:00

The access-key identifier and secret are intentionally excluded from this evidence.

## Security Risk

The current access path provides broad administrative authority and includes long-lived programmatic credentials.

Removing `AdministratorAccess` or disabling the active credential before validating an alternative access path could cause administrative lockout.

## Decision

Do not modify or disable the current administrator credential yet.

First design and validate a replacement access model.

## Project Boundary

Project 2 will not modify the IAM roles used by Project 1:

- `cloud-security-autoremediation-config`
- `cloud-security-autoremediation-remediation-lambda`

## Next Step

Design a least-privilege administrative/access model based on observed workload requirements and explicit security boundaries.
