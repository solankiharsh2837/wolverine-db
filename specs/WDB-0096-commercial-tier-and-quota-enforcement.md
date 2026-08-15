# WDB-0096: Commercial Tier and Quota Enforcement Protocol

Status: Normative Specification (v0.9.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the multi-tenant commercial tier model and rate/quota enforcement within the Trust Gateway.

## 2. Commercial Tier Policies

| Tier | Validator Topology | Quorum Policy | Daily Commitment Quota | Retention |
| :--- | :--- | :--- | :--- | :--- |
| **DEVELOPER** | Shared Cluster | 3-of-5 Quorum | 1,000 / day | 30 Days |
| **BUSINESS** | Multi-Region Shared | 4-of-5 Quorum | 50,000 / day | 7 Years |
| **ENTERPRISE** | Dedicated Validator Topology | Custom $(M, N)$ Policy | Unlimited | Permanent |

## 3. Quota Enforcement Rules

- If a tenant exceeds their daily commitment quota:
  - The Gateway returns `429 Too Many Requests`.
  - The customer Evidence Agent automatically transitions to **Local Queueing Mode**, ensuring zero disruption to database mutations.
