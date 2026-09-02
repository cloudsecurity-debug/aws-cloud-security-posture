# IAM Bedrock Access Analysis

## Finding

Prowler reported stale Bedrock access for:

- `iam_user_access_not_stale_to_bedrock`
- `iam_role_access_not_stale_to_bedrock`

## Evidence Source

AWS IAM service last accessed data.

Service last accessed job:

`a2d03053-8413-541e-92cc-14e12d28e8b1`

## Observed Results

The following services returned no recorded authenticated access:

- Amazon Bedrock (`bedrock`)
- Amazon Bedrock Agentcore (`bedrock-agentcore`)
- Amazon Bedrock Powered by AWS Mantle (`bedrock-mantle`)
- Amazon Bedrock Web Search (`bedrock-websearch`)

For all four services:

- LastAccessed: None
- Region: None

## Risk Assessment

No observed authenticated usage was identified for the Bedrock service namespaces in the available IAM service-last-accessed data.

This makes Bedrock access a candidate for permission reduction, but the evidence does not by itself prove that future access is unnecessary.

## Decision

Disposition remains:

`INVESTIGATE`

The project will not remove permissions solely from the absence of historical service access.

A permission-reduction change should require confirmation that Bedrock is not an intended workload dependency.

## Security Engineering Principle

Least privilege should be based on evidence and workload requirements, not simply on scanner score reduction.

## Status

OPEN - pending permission-path analysis and workload confirmation.
