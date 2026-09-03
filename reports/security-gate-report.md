# CSPM Security Gate Report

- Decisions evaluated: 16
- BLOCK: 9
- Pre-existing BLOCK: 9
- New BLOCK: 0
- INVESTIGATE: 1
- EXCEPTION: 2
- REPORT_ONLY: 4
- Enforcement: **new BLOCK findings only**
- Result: **PASS**


## Pre-existing Baseline Findings

- `iam_administrator_access_with_mfa` on `arn:aws:iam::010603499647:group/cloud-security-admins1`
- `iam_avoid_root_usage` on `arn:aws:iam::010603499647:root`
- `iam_aws_attached_policy_no_administrative_privileges` on `arn:aws:iam::aws:policy/AdministratorAccess`
- `iam_group_administrator_access_policy` on `arn:aws:iam::010603499647:group/cloud-security-admins1`
- `iam_root_hardware_mfa_enabled` on `arn:aws:iam::010603499647:mfa`
- `iam_user_access_not_stale_to_bedrock` on `arn:aws:iam::010603499647:user/cloud-security-admin`
- `iam_user_hardware_mfa_enabled` on `arn:aws:iam::010603499647:user/cloud-security-admin`
- `iam_user_mfa_enabled_console_access` on `arn:aws:iam::010603499647:user/cloud-security-admin`
- `iam_user_with_temporary_credentials` on `arn:aws:iam::010603499647:user/cloud-security-admin`

## Investigation Required

- `iam_role_access_not_stale_to_bedrock` on `arn:aws:iam::010603499647:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport` — Effective score 20 remains below the block threshold; evidence requires investigation.

## Accepted Exceptions

- `iam_role_cross_service_confused_deputy_prevention` on `arn:aws:iam::010603499647:role/cloud-security-autoremediation-config`
- `iam_role_cross_service_confused_deputy_prevention` on `arn:aws:iam::010603499647:role/cloud-security-autoremediation-remediation-lambda`
