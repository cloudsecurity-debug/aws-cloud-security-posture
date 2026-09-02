# AWS SecurityAudit Policy Analysis

## Purpose

Evaluate whether the AWS-managed `SecurityAudit` policy can provide the
read-only assessment capability for Project 2 without granting broad
administrative permissions.

## Observed Permissions

The AWS-managed `SecurityAudit` policy provides read-oriented access including:

- IAM `Get*` and `List*`
- EC2 `Describe*`
- CloudWatch `Describe*`
- S3 `Get*` and `List*`
- CloudFormation `Describe*`, `GetTemplate`, and `List*`
- RDS `Describe*`
- Route 53 read operations
- additional read-oriented operations across AWS services

The policy uses `Resource: *` for these read-only operations.

## Security Assessment

`SecurityAudit` is substantially narrower than `AdministratorAccess`, which
grants `Action: *` on `Resource: *`.

However, `SecurityAudit` is not a complete remediation policy. Project 2
requires carefully controlled write permissions for selected remediation
activities.

## Architectural Decision

Treat `SecurityAudit` as a candidate read-only assessment capability.

Do not use it as a replacement for `AdministratorAccess` until the required
Project 2 administrative and remediation workflows have been separately
identified and tested.

## Scope

This analysis is read-only.

No IAM permissions were changed.
