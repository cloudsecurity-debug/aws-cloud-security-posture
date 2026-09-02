# IAM Password Policy Remediation

## Finding

Prowler identified seven failing IAM password-policy controls in the initial
baseline assessment.

## Baseline

- Minimum password length: not configured
- Uppercase requirement: not configured
- Lowercase requirement: not configured
- Number requirement: not configured
- Symbol requirement: not configured
- Password reuse prevention: not configured
- Maximum password age: not configured

## Remediation

Applied the following account-level IAM password policy:

- Minimum password length: 14
- Uppercase characters: required
- Lowercase characters: required
- Numbers: required
- Symbols: required
- Password reuse prevention: 24 passwords
- Maximum password age: 90 days
- Users allowed to change their own passwords: yes

## Verification

AWS IAM `get-account-password-policy` confirmed all intended values after
remediation.

## Scope

This remediation changes the account-level IAM password policy only. It does
not modify administrator permissions, access keys, MFA configuration, or the
Project 1 autoremediation roles.

## Next Step

Re-run the Prowler IAM assessment and compare the post-remediation findings
against the baseline.
