# WDB-0073: Interleaved Mutation Classification Protocol

Status: Normative Specification (v0.7.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the formal state-classification taxonomy used by `analyzeHistory()` when inspecting history where valid and malicious mutations are interleaved.

## 2. Mutation Classification Taxonomy

Every candidate mutation is assigned one primary classification status:

| Status Code | Description | Replay Action |
| :--- | :--- | :--- |
| `VALID` | Passes history or independent proof, passes actor/scope/ticket rules, and dependencies are satisfied. | `PRESERVE` |
| `COMPROMISED` | Authored by a compromised credential, private key, or unauthorized actor. | `EXCLUDE` |
| `UNAUTHORIZED` | Scope violation, out of maintenance window, or invalid authorization signature. | `EXCLUDE` |
| `UNVERIFIABLE` | Missing required provenance trace, broken proof path, or unverifiable external commitment. | `EXCLUDE` |
| `DEPENDENCY_BLOCKED` | Mutation is authentic, but its semantic predecessor row was excluded or corrupted. | `BLOCK` |
| `STATE_CONFLICT` | Two competing authentic histories modify the same row version. | `CONFLICT_REQUIRES_REVIEW` |
| `REVOKED` | Explicitly marked revoked by an operator key-revocation certificate. | `EXCLUDE` |
| `MISSING` | Gap in historical sequence with no independent proof. | `EXCLUDE` |

## 3. Strict Determinism Invariant

Given identical input history, external checkpoints, and actor baselines, `analyzeHistory()` MUST produce the exact same `ReconstructionDecision[]` array and status codes on any machine or runtime environment.
