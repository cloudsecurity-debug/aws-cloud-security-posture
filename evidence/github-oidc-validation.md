# GitHub Actions OIDC Validation

## Objective

Validate that GitHub Actions can authenticate to AWS using OIDC without storing long-lived AWS credentials in GitHub.

## Repository

`cloudsecurity-debug/aws-cloud-security-posture`

## AWS Role

`Project2-GitHubActionsRole`

## Authentication Model

```text
GitHub Actions
      |
      | OIDC
      v
AWS IAM OIDC Provider
      |
      | AssumeRoleWithWebIdentity
      v
Project2-GitHubActionsRole
      |
      +-- SecurityAudit
      +-- Read-only assessment access
```

## Trust Restrictions

The role trust policy restricts access using:

- GitHub OIDC audience
- GitHub repository owner ID
- GitHub repository ID
- GitHub repository and `main` branch subject

## Validation

GitHub Actions successfully completed:

- `Configure AWS credentials with OIDC`
- `Verify AWS identity`

The workflow successfully assumed:

`Project2-GitHubActionsRole`

## Credential Security

No long-lived AWS access key is stored as a GitHub Actions credential.

The workflow uses short-lived OIDC-based AWS credentials.

## Result

`PASS — GitHub Actions successfully authenticated to AWS through the restricted OIDC trust policy.`

## Security Boundary

The GitHub Actions role is attached only to the AWS-managed:

`SecurityAudit`

policy.

It does not receive Project 2 remediation permissions or Project 1 workload-role permissions.
