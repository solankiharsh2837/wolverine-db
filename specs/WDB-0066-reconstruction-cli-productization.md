# WDB-0066: Reconstruction CLI Productization Protocol

Status: Normative Specification (v0.6.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the standard command-line interface (CLI) surface for computing the Verified State Frontier, generating reconstruction plans, auditing proofs, and executing approval-gated state restorations.

## 2. CLI Command Specifications

### 2.1 `wdb frontier --database <id>`
- Queries local database history, external WORM vault, and blockchain anchor consensus.
- Evaluates the 7 frontier verification pillars.
- Outputs the highest verifiable commit sequence ($S_{\text{frontier}}$) and any detected tampering boundaries.

### 2.2 `wdb reconstruct --database <id>`
- Executes forward authorized replay from the latest verified checkpoint to the recovery boundary.
- Emits the machine-readable `ReconstructionManifest`.

### 2.3 `wdb recovery-plan --database <id>`
- Formulates the structured, non-destructive `AdvisoryRecoveryProposal` (`WDB-0033`).
- Submits the plan to the Policy Gate (`WDB-0034`).

### 2.4 `wdb recovery-verify --recovery-id <id>`
- Audits the `ReconstructionProof` and verifies all Ed25519 signatures and external anchors.

### 2.5 `wdb recovery-certificate --recovery-id <id>`
- Outputs the canonical `StateRecoveryCertificate` in both JSON and human-readable terminal table formats.

### 2.6 `wdb recover --recovery-id <id>`
- Executes atomic forward-additive state recovery in PostgreSQL/MySQL/SQLite upon presenting valid multi-party Ed25519 approval envelopes.
- Emits post-recovery checkpoint and publishes external blockchain anchor.
