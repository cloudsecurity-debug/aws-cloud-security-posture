# AWS Cloud Security Posture Management (CSPM)

> A policy-driven AWS CSPM pipeline that discovers cloud-security findings, enriches them with security context, calculates explainable risk, applies governance decisions, and enforces security policy through CI/CD.

[![Cloud Security Gate](https://github.com/cloudsecurity-debug/aws-cloud-security-posture/actions/workflows/security-gate.yml/badge.svg)](https://github.com/cloudsecurity-debug/aws-cloud-security-posture/actions/workflows/security-gate.yml)

## Why I Built This

Cloud security tools can produce hundreds of findings, but detection alone does not create a security program.

This project demonstrates the engineering layer between **finding discovery and security enforcement**:

**Discover → Normalize → Enrich → Risk-score → Prioritize → Govern → Verify → Evidence**

The goal is to make cloud-security decisions **repeatable, explainable, auditable, and safe to enforce in CI/CD**.

---

## Architecture

```text
AWS Account
     │
     ▼
Prowler CSPM Assessment
(IAM • S3 • Lambda • EventBridge)
     │
     ▼
Finding Normalization
     │
     ▼
Security Context
(asset criticality • exposure • business impact • exploitability)
     │
     ▼
Explainable Risk Engine
     │
     ▼
Governance Decision
 ┌──────────┬─────────────┬───────────┬─────────────┐
 │  BLOCK   │ INVESTIGATE │ EXCEPTION │ REPORT_ONLY │
 └──────────┴─────────────┴───────────┴─────────────┘
     │
     ▼
Security Gate
     │
     ├── New BLOCK → CI FAIL
     │
     └── No New BLOCK → CI PASS
     │
     ▼
Evidence + Verification
