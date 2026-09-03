# CSPM Risk Decision Report

- Findings evaluated: 16
- BLOCK: 9
- INVESTIGATE: 1
- EXCEPTION: 2
- REPORT_ONLY: 4
- Result: **BLOCK**

| Score | Base | Context | Severity | Decision | Disposition | Owner | Finding | Resource |
|---:|---:|---:|---|---|---|---|---|---|
| 60 | 30 | 30 | HIGH | BLOCK | MANUAL_REMEDIATE | IAM | `iam_user_hardware_mfa_enabled` | `arn:aws:iam::010603499647:user/cloud-security-admin` |
| 60 | 30 | 30 | HIGH | BLOCK | MANUAL_REMEDIATE | IAM | `iam_user_mfa_enabled_console_access` | `arn:aws:iam::010603499647:user/cloud-security-admin` |
| 60 | 30 | 30 | HIGH | BLOCK | MANUAL_REMEDIATE | IAM | `iam_user_with_temporary_credentials` | `arn:aws:iam::010603499647:user/cloud-security-admin` |
| 50 | 20 | 30 | MEDIUM | BLOCK | INVESTIGATE | IAM | `iam_user_access_not_stale_to_bedrock` | `arn:aws:iam::010603499647:user/cloud-security-admin` |
| 40 | 40 | 0 | CRITICAL | BLOCK | MANUAL_REMEDIATE | IAM | `iam_aws_attached_policy_no_administrative_privileges` | `arn:aws:iam::aws:policy/AdministratorAccess` |
| 40 | 10 | 30 | LOW | REPORT_ONLY | REPORT_ONLY | IAM | `iam_policy_attached_only_to_group_or_roles` | `arn:aws:iam::010603499647:user/cloud-security-admin` |
| 40 | 30 | 10 | HIGH | EXCEPTION | EXCEPTION | PROJECT_1 | `iam_role_cross_service_confused_deputy_prevention` | `arn:aws:iam::010603499647:role/cloud-security-autoremediation-config` |
| 40 | 30 | 10 | HIGH | EXCEPTION | EXCEPTION | PROJECT_1 | `iam_role_cross_service_confused_deputy_prevention` | `arn:aws:iam::010603499647:role/cloud-security-autoremediation-remediation-lambda` |
| 40 | 40 | 0 | CRITICAL | BLOCK | MANUAL_REMEDIATE | ACCOUNT_SECURITY | `iam_root_hardware_mfa_enabled` | `arn:aws:iam::010603499647:mfa` |
| 30 | 30 | 0 | HIGH | BLOCK | MANUAL_REMEDIATE | IAM | `iam_administrator_access_with_mfa` | `arn:aws:iam::010603499647:group/cloud-security-admins1` |
| 30 | 30 | 0 | HIGH | BLOCK | MANUAL_REMEDIATE | ACCOUNT_SECURITY | `iam_avoid_root_usage` | `arn:aws:iam::010603499647:root` |
| 30 | 30 | 0 | HIGH | BLOCK | MANUAL_REMEDIATE | IAM | `iam_group_administrator_access_policy` | `arn:aws:iam::010603499647:group/cloud-security-admins1` |
| 20 | 20 | 0 | MEDIUM | INVESTIGATE | INVESTIGATE | IAM | `iam_role_access_not_stale_to_bedrock` | `arn:aws:iam::010603499647:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport` |
| 10 | 10 | 0 | LOW | REPORT_ONLY | REPORT_ONLY | IDENTITY | `iam_check_saml_providers_sts` | `arn:aws:iam::010603499647:root` |
| 10 | 10 | 0 | LOW | REPORT_ONLY | REPORT_ONLY | GOVERNANCE | `iam_securityaudit_role_created` | `arn:aws:iam::aws:policy/SecurityAudit` |
| 10 | 10 | 0 | LOW | REPORT_ONLY | REPORT_ONLY | GOVERNANCE | `iam_support_role_created` | `arn:aws:iam::aws:policy/AWSSupportAccess` |

## Decision Rationale

### `iam_user_hardware_mfa_enabled` — BLOCK

- **Resource:** `arn:aws:iam::010603499647:user/cloud-security-admin`
- **Severity:** HIGH
- **Base score:** 30
- **Context score:** 30
- **Context contributions:** asset_criticality=+10, exposure=+0, business_impact=+10, exploitability=+10
- **Disposition:** MANUAL_REMEDIATE
- **Lifecycle:** OPEN
- **Rationale:** Effective risk score 60 reaches the block threshold of 40.

### `iam_user_mfa_enabled_console_access` — BLOCK

- **Resource:** `arn:aws:iam::010603499647:user/cloud-security-admin`
- **Severity:** HIGH
- **Base score:** 30
- **Context score:** 30
- **Context contributions:** asset_criticality=+10, exposure=+0, business_impact=+10, exploitability=+10
- **Disposition:** MANUAL_REMEDIATE
- **Lifecycle:** OPEN
- **Rationale:** Effective risk score 60 reaches the block threshold of 40.

### `iam_user_with_temporary_credentials` — BLOCK

- **Resource:** `arn:aws:iam::010603499647:user/cloud-security-admin`
- **Severity:** HIGH
- **Base score:** 30
- **Context score:** 30
- **Context contributions:** asset_criticality=+10, exposure=+0, business_impact=+10, exploitability=+10
- **Disposition:** MANUAL_REMEDIATE
- **Lifecycle:** OPEN
- **Rationale:** Effective risk score 60 reaches the block threshold of 40.

### `iam_user_access_not_stale_to_bedrock` — BLOCK

- **Resource:** `arn:aws:iam::010603499647:user/cloud-security-admin`
- **Severity:** MEDIUM
- **Base score:** 20
- **Context score:** 30
- **Context contributions:** asset_criticality=+10, exposure=+0, business_impact=+10, exploitability=+10
- **Disposition:** INVESTIGATE
- **Lifecycle:** OPEN
- **Rationale:** Effective risk score 50 reaches the block threshold of 40.

### `iam_aws_attached_policy_no_administrative_privileges` — BLOCK

- **Resource:** `arn:aws:iam::aws:policy/AdministratorAccess`
- **Severity:** CRITICAL
- **Base score:** 40
- **Context score:** 0
- **Context contributions:** asset_criticality=+0, exposure=+0, business_impact=+0, exploitability=+0
- **Disposition:** MANUAL_REMEDIATE
- **Lifecycle:** OPEN
- **Rationale:** Effective risk score 40 reaches the block threshold of 40.

### `iam_policy_attached_only_to_group_or_roles` — REPORT_ONLY

- **Resource:** `arn:aws:iam::010603499647:user/cloud-security-admin`
- **Severity:** LOW
- **Base score:** 10
- **Context score:** 30
- **Context contributions:** asset_criticality=+10, exposure=+0, business_impact=+10, exploitability=+10
- **Disposition:** REPORT_ONLY
- **Lifecycle:** OPEN
- **Rationale:** Explicit REPORT_ONLY governance disposition keeps the finding non-blocking.

### `iam_role_cross_service_confused_deputy_prevention` — EXCEPTION

- **Resource:** `arn:aws:iam::010603499647:role/cloud-security-autoremediation-config`
- **Severity:** HIGH
- **Base score:** 30
- **Context score:** 10
- **Context contributions:** asset_criticality=+5, exposure=+0, business_impact=+5, exploitability=+0
- **Disposition:** EXCEPTION
- **Lifecycle:** OPEN
- **Rationale:** Explicit governance exception takes precedence over contextual risk.

### `iam_role_cross_service_confused_deputy_prevention` — EXCEPTION

- **Resource:** `arn:aws:iam::010603499647:role/cloud-security-autoremediation-remediation-lambda`
- **Severity:** HIGH
- **Base score:** 30
- **Context score:** 10
- **Context contributions:** asset_criticality=+5, exposure=+0, business_impact=+5, exploitability=+0
- **Disposition:** EXCEPTION
- **Lifecycle:** OPEN
- **Rationale:** Explicit governance exception takes precedence over contextual risk.

### `iam_root_hardware_mfa_enabled` — BLOCK

- **Resource:** `arn:aws:iam::010603499647:mfa`
- **Severity:** CRITICAL
- **Base score:** 40
- **Context score:** 0
- **Context contributions:** asset_criticality=+0, exposure=+0, business_impact=+0, exploitability=+0
- **Disposition:** MANUAL_REMEDIATE
- **Lifecycle:** OPEN
- **Rationale:** Effective risk score 40 reaches the block threshold of 40.

### `iam_administrator_access_with_mfa` — BLOCK

- **Resource:** `arn:aws:iam::010603499647:group/cloud-security-admins1`
- **Severity:** HIGH
- **Base score:** 30
- **Context score:** 0
- **Context contributions:** asset_criticality=+0, exposure=+0, business_impact=+0, exploitability=+0
- **Disposition:** MANUAL_REMEDIATE
- **Lifecycle:** OPEN
- **Rationale:** Effective score 30 remains below the block threshold and follows the severity default action.

### `iam_avoid_root_usage` — BLOCK

- **Resource:** `arn:aws:iam::010603499647:root`
- **Severity:** HIGH
- **Base score:** 30
- **Context score:** 0
- **Context contributions:** asset_criticality=+0, exposure=+0, business_impact=+0, exploitability=+0
- **Disposition:** MANUAL_REMEDIATE
- **Lifecycle:** OPEN
- **Rationale:** Effective score 30 remains below the block threshold and follows the severity default action.

### `iam_group_administrator_access_policy` — BLOCK

- **Resource:** `arn:aws:iam::010603499647:group/cloud-security-admins1`
- **Severity:** HIGH
- **Base score:** 30
- **Context score:** 0
- **Context contributions:** asset_criticality=+0, exposure=+0, business_impact=+0, exploitability=+0
- **Disposition:** MANUAL_REMEDIATE
- **Lifecycle:** OPEN
- **Rationale:** Effective score 30 remains below the block threshold and follows the severity default action.

### `iam_role_access_not_stale_to_bedrock` — INVESTIGATE

- **Resource:** `arn:aws:iam::010603499647:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport`
- **Severity:** MEDIUM
- **Base score:** 20
- **Context score:** 0
- **Context contributions:** asset_criticality=+0, exposure=+0, business_impact=+0, exploitability=+0
- **Disposition:** INVESTIGATE
- **Lifecycle:** OPEN
- **Rationale:** Effective score 20 remains below the block threshold; evidence requires investigation.

### `iam_check_saml_providers_sts` — REPORT_ONLY

- **Resource:** `arn:aws:iam::010603499647:root`
- **Severity:** LOW
- **Base score:** 10
- **Context score:** 0
- **Context contributions:** asset_criticality=+0, exposure=+0, business_impact=+0, exploitability=+0
- **Disposition:** REPORT_ONLY
- **Lifecycle:** OPEN
- **Rationale:** Explicit REPORT_ONLY governance disposition keeps the finding non-blocking.

### `iam_securityaudit_role_created` — REPORT_ONLY

- **Resource:** `arn:aws:iam::aws:policy/SecurityAudit`
- **Severity:** LOW
- **Base score:** 10
- **Context score:** 0
- **Context contributions:** asset_criticality=+0, exposure=+0, business_impact=+0, exploitability=+0
- **Disposition:** REPORT_ONLY
- **Lifecycle:** OPEN
- **Rationale:** Explicit REPORT_ONLY governance disposition keeps the finding non-blocking.

### `iam_support_role_created` — REPORT_ONLY

- **Resource:** `arn:aws:iam::aws:policy/AWSSupportAccess`
- **Severity:** LOW
- **Base score:** 10
- **Context score:** 0
- **Context contributions:** asset_criticality=+0, exposure=+0, business_impact=+0, exploitability=+0
- **Disposition:** REPORT_ONLY
- **Lifecycle:** OPEN
- **Rationale:** Explicit REPORT_ONLY governance disposition keeps the finding non-blocking.

