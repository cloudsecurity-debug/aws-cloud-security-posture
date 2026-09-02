# Least-Privilege Access Design

## Objective

Replace broad `AdministratorAccess` dependency with an evidence-based access model without causing administrative lockout.

## Current State

The only IAM user is:

`cloud-security-admin`

The user belongs to:

`cloud-security-admins1`

The group has:

`AdministratorAccess`

The verified policy grants:

- `Action: *`
- `Resource: *`

The user also has:

`IAMUserChangePassword`

## Observed Service Usage

IAM service-last-accessed evidence identified activity involving:

- IAM
- CloudShell
- AWS Config
- Amazon EventBridge
- Amazon EC2
- Cost Explorer
- Cost Optimization Hub
- Free Tier
- AWS Health

## Services Requiring Additional Evidence

### EC2

Historical service access was observed, but:

- no EC2 instances were found in `eu-north-1`
- no EC2 instances were found in `us-east-1`
- no EC2 API events were returned in the available CloudTrail lookup

Decision:

Do not grant broad EC2 permissions based solely on historical service-level access.

### Bedrock

No recorded authenticated access was found for:

- Bedrock
- Bedrock Agentcore
- Bedrock Powered by AWS Mantle
- Bedrock Web Search

Decision:

Keep Bedrock access under investigation rather than automatically granting or removing permissions.

## Project 1 Boundary

Project 1 uses dedicated IAM roles:

- `cloud-security-autoremediation-config`
- `cloud-security-autoremediation-remediation-lambda`

These roles are outside the remediation scope of Project 2.

Project 2 will not modify their permissions.

## Proposed Migration Strategy

The migration must be staged:

1. Design replacement permissions.
2. Create the replacement policy without removing existing access.
3. Validate the replacement access path.
4. Confirm CloudShell/API operations required by the project.
5. Only then consider removing `AdministratorAccess`.
6. Retain a tested recovery path.
7. Re-run Prowler.
8. Compare before/after findings.
9. Document the result.

## Security Principles

- Do not grant permissions solely because a service appears in historical access data.
- Do not remove permissions solely to improve scanner scores.
- Validate authorization changes before removing existing access.
- Separate Project 1 infrastructure permissions from Project 2 administrative permissions.
- Prefer resource-scoped and action-scoped permissions where practical.
- Keep human administrative access separate from workload/service roles.
- Treat long-lived IAM access keys as a migration risk.

## Current Decision

No authorization change is being made yet.

The next phase is to define the minimum permissions required for the actual Project 2 workflow and determine whether AWS IAM Identity Center or a role-based access model can replace the long-lived IAM-user administrator path.
