# WDB-0062: Recovery Boundary Detection Protocol

Status: Normative Specification (v0.6.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the formal criteria for detecting the exact **Recovery Boundary** ($B_{\text{rec}}$). The Recovery Boundary separates valid historical transactions that occurred before an adversarial intrusion from fraudulent, unauthorized, or corrupted mutations that occurred during or after the intrusion.

## 2. Boundary Classification Taxonomy

The boundary detection engine identifies the first non-conforming change record $R_k$ and classifies the boundary trigger:

| Trigger Code | Description | Severity | Action |
| :--- | :--- | :--- | :--- |
| `HASH_CHAIN_DISCONTINUITY` | Previous hash link does not match `computeChangeHash(R_{k-1})`. | `CRITICAL` | Halt frontier at $k-1$; flag history tampering. |
| `SEQUENCE_GAP_OR_OUT_OF_ORDER` | Commit sequence skips numbers or regresses. | `CRITICAL` | Halt frontier at $k-1$; flag sequence injection. |
| `UNAUTHORIZED_SCOPE_MUTATION` | Mutation affects tables outside actor baseline policy. | `HIGH` | Halt frontier at $k-1$; exclude unauthorized change. |
| `MISSING_PROVENANCE_TICKET` | High-privilege mutation lacks required ticket ID. | `HIGH` | Halt frontier at $k-1$; flag unverified execution. |
| `FORGED_AUTHORIZATION_ENVELOPE` | Ed25519 signature fails verification against trusted keys. | `CRITICAL` | Halt frontier at $k-1$; flag cryptographic forgery. |
| `POST_COMPROMISE_MUTATION` | Mutation executed by credential known to be compromised. | `CRITICAL` | Halt frontier at $k-1$; isolate attacker session. |

## 3. Strict Boundary Invariant

- The recovery engine **MUST NEVER** attempt to "guess" or "skip over" a broken mutation to replay subsequent mutations.
- The state frontier **STOPS** unconditionally at the boundary $k-1$.
- All changes with sequence $\le k-1$ are marked **PRESERVED**.
- All changes with sequence $\ge k$ are marked **EXCLUDED**.
