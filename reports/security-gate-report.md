# CSPM Security Gate Report

- Decisions evaluated: 16
- BLOCK: 9
- INVESTIGATE: 1
- EXCEPTION: 2
- REPORT_ONLY: 4
- Result: **BLOCK**

## Blocking Decisions

| Severity | Finding | Resource | Disposition | Owner |
|---|---|---|---|---|
| HIGH | `iam_administrator_access_with_mfa` | `arn:aws:iam::010603499647:group/cloud-security-admins1` | MANUAL_REMEDIATE | IAM |
| HIGH | `iam_avoid_root_usage` | `arn:aws:iam::010603499647:root` | MANUAL_REMEDIATE | ACCOUNT_SECURITY |
| CRITICAL | `iam_aws_attached_policy_no_administrative_privileges` | `arn:aws:iam::aws:policy/AdministratorAccess` | MANUAL_REMEDIATE | IAM |
| HIGH | `iam_group_administrator_access_policy` | `arn:aws:iam::010603499647:group/cloud-security-admins1` | MANUAL_REMEDIATE | IAM |
| CRITICAL | `iam_root_hardware_mfa_enabled` | `arn:aws:iam::010603499647:mfa` | MANUAL_REMEDIATE | ACCOUNT_SECURITY |
| MEDIUM | `iam_user_access_not_stale_to_bedrock` | `arn:aws:iam::010603499647:user/cloud-security-admin` | INVESTIGATE | IAM |
| HIGH | `iam_user_hardware_mfa_enabled` | `arn:aws:iam::010603499647:user/cloud-security-admin` | MANUAL_REMEDIATE | IAM |
| HIGH | `iam_user_mfa_enabled_console_access` | `arn:aws:iam::010603499647:user/cloud-security-admin` | MANUAL_REMEDIATE | IAM |
| HIGH | `iam_user_with_temporary_credentials` | `arn:aws:iam::010603499647:user/cloud-security-admin` | MANUAL_REMEDIATE | IAM |

## Investigation Required

- `iam_role_access_not_stale_to_bedrock` on `arn:aws:iam::010603499647:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport` — Effective score 20 remains below the block threshold; evidence requires investigation.

## Accepted Exceptions

- `iam_role_cross_service_confused_deputy_prevention` on `arn:aws:iam::010603499647:role/cloud-security-autoremediation-config`
- `iam_role_cross_service_confused_deputy_prevention` on `arn:aws:iam::010603499647:role/cloud-security-autoremediation-remediation-lambda`
