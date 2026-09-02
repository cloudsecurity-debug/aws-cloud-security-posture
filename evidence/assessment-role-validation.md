# Project 2 Assessment Role Validation

## Objective

Validate that the Project 2 assessment role provides security assessment visibility without granting general IAM write permissions.

## Role

`Project2-SecurityAssessmentRole`

## Permission Baseline

AWS-managed policy:

`arn:aws:iam::aws:policy/SecurityAudit`

## Trust Boundary

The role trust policy permits:

`arn:aws:iam::010603499647:user/cloud-security-admin`

## Validation Results

### Identity Validation

AWS STS confirmed the active session as:

`assumed-role/Project2-SecurityAssessmentRole/project2-assessment-test`

### Read Test

Command:

`aws iam list-users`

Result:

The assessment role successfully returned the IAM user:

`cloud-security-admin`

Disposition:

`PASS — required read-only assessment visibility is available.`

### Write Test

Simulated action:

`iam:CreateUser`

Result:

`implicitDeny`

Disposition:

`PASS — the assessment role does not have permission to create IAM users.`

## Security Boundary

The assessment role is intentionally separated from remediation authority.

It is designed to:

- inspect AWS security posture,
- support CSPM assessment,
- provide read-only visibility.

It is not designed to:

- create IAM users,
- modify IAM privileges,
- delete resources,
- perform Project 1 remediation.

## Project 1 Boundary

Project 1 roles remain outside Project 2 remediation scope:

- `cloud-security-autoremediation-config`
- `cloud-security-autoremediation-remediation-lambda`

No permissions on those roles were modified.

## Conclusion

The Project 2 assessment access path has been successfully validated.

Read access works, while a representative IAM write action is denied.
