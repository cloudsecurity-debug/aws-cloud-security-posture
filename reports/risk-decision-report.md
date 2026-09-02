# CSPM Risk Decision Report

- Findings evaluated: 16
- BLOCK: 8
- INVESTIGATE: 2
- EXCEPTION: 2
- REPORT_ONLY: 4
- Result: **BLOCK**

| Score | Severity | Decision | Disposition | Owner | Finding | Resource |
|---:|---|---|---|---|---|---|
| 40 | CRITICAL | BLOCK | MANUAL_REMEDIATE | IAM | `iam_aws_attached_policy_no_administrative_privileges` | `arn:aws:iam::aws:policy/AdministratorAccess` |
| 40 | CRITICAL | BLOCK | MANUAL_REMEDIATE | ACCOUNT_SECURITY | `iam_root_hardware_mfa_enabled` | `arn:aws:iam::010603499647:mfa` |
| 30 | HIGH | BLOCK | MANUAL_REMEDIATE | IAM | `iam_administrator_access_with_mfa` | `arn:aws:iam::010603499647:group/cloud-security-admins1` |
| 30 | HIGH | BLOCK | MANUAL_REMEDIATE | ACCOUNT_SECURITY | `iam_avoid_root_usage` | `arn:aws:iam::010603499647:root` |
| 30 | HIGH | BLOCK | MANUAL_REMEDIATE | IAM | `iam_group_administrator_access_policy` | `arn:aws:iam::010603499647:group/cloud-security-admins1` |
| 30 | HIGH | EXCEPTION | EXCEPTION | PROJECT_1 | `iam_role_cross_service_confused_deputy_prevention` | `arn:aws:iam::010603499647:role/cloud-security-autoremediation-config` |
| 30 | HIGH | EXCEPTION | EXCEPTION | PROJECT_1 | `iam_role_cross_service_confused_deputy_prevention` | `arn:aws:iam::010603499647:role/cloud-security-autoremediation-remediation-lambda` |
| 30 | HIGH | BLOCK | MANUAL_REMEDIATE | IAM | `iam_user_hardware_mfa_enabled` | `arn:aws:iam::010603499647:user/cloud-security-admin` |
| 30 | HIGH | BLOCK | MANUAL_REMEDIATE | IAM | `iam_user_mfa_enabled_console_access` | `arn:aws:iam::010603499647:user/cloud-security-admin` |
| 30 | HIGH | BLOCK | MANUAL_REMEDIATE | IAM | `iam_user_with_temporary_credentials` | `arn:aws:iam::010603499647:user/cloud-security-admin` |
| 20 | MEDIUM | INVESTIGATE | INVESTIGATE | IAM | `iam_role_access_not_stale_to_bedrock` | `arn:aws:iam::010603499647:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport` |
| 20 | MEDIUM | INVESTIGATE | INVESTIGATE | IAM | `iam_user_access_not_stale_to_bedrock` | `arn:aws:iam::010603499647:user/cloud-security-admin` |
| 10 | LOW | REPORT_ONLY | REPORT_ONLY | IDENTITY | `iam_check_saml_providers_sts` | `arn:aws:iam::010603499647:root` |
| 10 | LOW | REPORT_ONLY | REPORT_ONLY | IAM | `iam_policy_attached_only_to_group_or_roles` | `arn:aws:iam::010603499647:user/cloud-security-admin` |
| 10 | LOW | REPORT_ONLY | REPORT_ONLY | GOVERNANCE | `iam_securityaudit_role_created` | `arn:aws:iam::aws:policy/SecurityAudit` |
| 10 | LOW | REPORT_ONLY | REPORT_ONLY | GOVERNANCE | `iam_support_role_created` | `arn:aws:iam::aws:policy/AWSSupportAccess` |
