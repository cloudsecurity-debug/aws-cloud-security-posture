# IAM CloudTrail Investigation

## Subject

IAM user: `cloud-security-admin`

## Purpose

Determine whether recent CloudTrail activity can be used to identify the
minimum API permissions required to replace `AdministratorAccess`.

## Observation

The recent CloudTrail event window was dominated by read-only IAM and
CloudTrail investigation activity, including:

- `GetServiceLastAccessedDetails`
- `GenerateServiceLastAccessedDetails`
- `LookupEvents`
- `ListPolicies`
- `GetGroup`
- `GetRole`
- `ListUserTags`
- `ListRoleTags`

## Assessment

The observed events primarily represent the current security assessment and
Prowler investigation rather than an independent production workload.

Therefore, these events must not be treated as sufficient evidence for
constructing a least-privilege policy.

## Security Decision

Do not derive a replacement IAM policy from this CloudTrail sample.

Additional evidence is required to distinguish:

1. security-administration activity,
2. Project 1 infrastructure activity,
3. normal workload activity, and
4. permissions that are actually required long-term.

`AdministratorAccess` remains unchanged while this analysis continues.

## Scope

This investigation is read-only and does not modify IAM permissions.
