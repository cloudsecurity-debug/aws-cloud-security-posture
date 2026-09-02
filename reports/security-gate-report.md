# CSPM Security Gate Report

- Findings evaluated: 16
- BLOCK: 8
- INVESTIGATE: 2
- EXCEPTION: 2
- REPORT_ONLY: 4
- Result: **BLOCK**

## Blocking Findings

| Severity | Check ID | Resource |
|---|---|---|
| HIGH | iam_administrator_access_with_mfa | cloud-security-admins1 |
| HIGH | iam_avoid_root_usage | <root_account> |
| CRITICAL | iam_aws_attached_policy_no_administrative_privileges | AdministratorAccess |
| HIGH | iam_group_administrator_access_policy | cloud-security-admins1 |
| CRITICAL | iam_root_hardware_mfa_enabled | <root_account> |
| HIGH | iam_user_hardware_mfa_enabled | cloud-security-admin |
| HIGH | iam_user_mfa_enabled_console_access | cloud-security-admin |
| HIGH | iam_user_with_temporary_credentials | cloud-security-admin |

## Accepted Exceptions

- `iam_role_cross_service_confused_deputy_prevention` on `cloud-security-autoremediation-config` — Project 1 role is outside Project 2 remediation scope
- `iam_role_cross_service_confused_deputy_prevention` on `cloud-security-autoremediation-remediation-lambda` — Project 1 role is outside Project 2 remediation scope
