# Prowler Runtime Strategy

## Decision

Prowler is pinned in `requirements.txt` for reproducibility, but Project 2 does not depend on a persistent Prowler installation inside AWS CloudShell.

## Reason

CloudShell has constrained local storage, and the Prowler dependency tree can consume significant disk space during installation.

Repeated local installations are therefore avoided.

## Runtime Model

The preferred execution environment is a clean CI runner with sufficient temporary storage.

GitHub Actions will:

1. create a clean Python environment,
2. install the pinned Prowler version,
3. authenticate to AWS using short-lived credentials,
4. assume `Project2-SecurityAssessmentRole`,
5. run the assessment,
6. preserve the relevant assessment artifacts,
7. apply the project's security gate.

## Credential Boundary

Prowler must not use the long-lived administrator access key as a CI credential.

The intended CI authentication model is:

```text
GitHub Actions
      |
      | OIDC / short-lived credentials
      v
Project 2 assessment role
      |
      +-- SecurityAudit
      |
      +-- Read-only CSPM assessment
R
