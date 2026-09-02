# IAM Service Access Analysis

## Subject

IAM user: `cloud-security-admin`

## Purpose

Determine which AWS services have recorded access before attempting to
replace the user's broad `AdministratorAccess` permission with a
least-privilege policy.

## Recorded Service Access

| Service | Region | Last Accessed |
|---|---|---|
| AWS Cost Explorer Service | us-east-1 | 2026-08-31T14:18:23+00:00 |
| AWS CloudShell | eu-north-1 | 2026-08-31T15:00:04+00:00 |
| AWS Config | eu-north-1 | 2026-09-01T12:43:10+00:00 |
| AWS Cost Optimization Hub | us-east-1 | 2026-08-31T14:17:16+00:00 |
| Amazon EC2 | eu-north-1 | 2026-09-01T19:20:25+00:00 |
| Amazon EventBridge | eu-north-1 | 2026-09-01T14:57:28+00:00 |
| AWS Free Tier | us-east-1 | 2026-08-31T14:18:16+00:00 |
| AWS Health APIs and Notifications | us-east-1 | 2026-08-31T14:18:16+00:00 |

## Interpretation

Service-last-accessed data is evidence of observed service access, not proof
that every recorded service is required for the user's long-term role.

AWS Config and EventBridge access is consistent with the existing Project 1
security automation workload.

CloudShell access reflects the current administrative environment.

Cost and account-health services reflect account administration activity.

EC2 access requires additional investigation before being used as the basis
for a least-privilege policy.

## Security Decision

Do not remove `AdministratorAccess` yet.

A replacement policy must be designed from observed permissions and required
workflows rather than from service names alone. The current administrator
credential must remain available until the replacement access path has been
validated.

## Scope

This analysis is read-only and does not modify IAM permissions.
