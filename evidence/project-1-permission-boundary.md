# Project 1 Permission Boundary

## Purpose

Document the IAM permissions of the existing Project 1 remediation role before
performing Project 2 IAM remediation.

## Project 1 Lambda Role

Role:

`cloud-security-autoremediation-remediation-lambda`

The role has one inline policy:

`cloud-security-autoremediation-remediation-policy`

### Permissions

The policy grants:

- `logs:CreateLogGroup`
- `logs:CreateLogStream`
- `logs:PutLogEvents`

for CloudWatch Logs resources in `eu-north-1`.

It also grants:

- `s3:GetBucketPublicAccessBlock`
- `s3:PutBucketPublicAccessBlock`

for S3 bucket resources.

## Security Assessment

The Project 1 remediation role follows a significantly narrower permission
model than the Project 2 administrative IAM user, which currently receives
AWS-managed `AdministratorAccess`.

Project 2 will not modify the Project 1 role or its policy.

## Decision

Project 1 permissions are treated as an existing workload boundary.

Project 2 IAM remediation must be designed independently and must not reduce,
replace, or repurpose Project 1 permissions.

## Verification

The policy was inspected using the AWS IAM read-only
`get-role-policy` operation.

No IAM permissions were modified during this investigation.
