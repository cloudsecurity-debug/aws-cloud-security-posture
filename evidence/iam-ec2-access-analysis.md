# IAM EC2 Access Analysis

## Evidence Reviewed

IAM service-last-accessed data recorded historical authenticated access to Amazon EC2:

- Region: `eu-north-1`
- LastAccessed: `2026-09-01T19:20:25+00:00`

## CloudTrail Investigation

A CloudTrail lookup for:

`cloud-security-admin`

filtered to:

`ec2.amazonaws.com`

returned no EC2 API events in the available lookup results.

## Current EC2 Inventory

### eu-north-1

A default VPC exists, but no EC2 instances were returned.

### us-east-1

A default VPC exists, but no EC2 instances were returned.

## Risk Assessment

Historical service-level access indicates that EC2 was accessed, but the current environment contains no EC2 instance workload in the regions investigated.

The available CloudTrail lookup also did not provide corresponding EC2 API activity for the administrator user.

Therefore, there is insufficient evidence to justify broad EC2 permissions in a replacement least-privilege policy.

## Decision

Do not include broad EC2 administrative permissions in the replacement access model based solely on historical service access.

If an EC2 workload is introduced later, permissions should be scoped to the specific operational requirements and resources.

## Security Engineering Principle

Service-level access history is useful for discovery but should not automatically become an authorization policy.

Least privilege requires evidence of the actual operations and resources that need to be managed.
