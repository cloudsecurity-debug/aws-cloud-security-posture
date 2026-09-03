# AWS Cloud Security Posture

[![Cloud Security Gate](https://github.com/cloudsecurity-debug/aws-cloud-security-posture/actions/workflows/security-gate.yml/badge.svg)](https://github.com/cloudsecurity-debug/aws-cloud-security-posture/actions/workflows/security-gate.yml)

A production-style AWS Cloud Security Posture Management (CSPM) pipeline that discovers cloud security findings, enriches them with security context, calculates explainable risk, applies governance decisions, and enforces security policy through CI/CD.

The project demonstrates a complete security control loop:

**Discover → Normalize → Enrich → Risk Score → Govern → Gate → Verify → Preserve Evidence**

---

## Why This Project Exists

Cloud security scanners can produce hundreds of findings, but detection alone does not create a security program.

Security teams need to answer:

- Which findings are actually important?
- Which resources are affected?
- Who owns the risk?
- What should block deployment?
- Which findings require investigation?
- Which risks are explicitly accepted?
- Can the organization prove what happened?

This project turns raw CSPM findings into **explainable, governed, CI-enforced security decisions**.

---

## Architecture

```text
                         AWS ACCOUNT
                             │
                             ▼
                       ┌─────────────┐
                       │   Prowler   │
                       │    CSPM     │
                       └──────┬──────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │ Finding Normalizer│
                    └─────────┬─────────┘
                              │
                              ▼
                  ┌───────────────────────┐
                  │ Security Context      │
                  │ + Evidence Enrichment │
                  └───────────┬───────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │ Explainable Risk│
                    │     Engine      │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Governance      │
                    │ Decision        │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
           BLOCK        INVESTIGATE      EXCEPTION
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    ┌─────────────────┐
                    │ Security Gate   │
                    └────────┬────────┘
                             │
                             ▼
                    GitHub Actions CI/CD
                             │
                             ▼
                    Evidence Artifacts
