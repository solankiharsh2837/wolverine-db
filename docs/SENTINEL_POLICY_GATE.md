# WolverineDB // Sentinel Autonomous Policy Gate & TOCTOU Defense

> **Source Code is Authoritative.**  
> This document specifies the behavioral anomaly detection engine, deterministic policy evaluation rules, TOCTOU protections, and autonomous repair blast-radius caps of **WolverineDB v1.3.0**.

---

## 1. Overview of Sentinel Architecture

The **Sentinel Subsystem** ([`src/sentinel/`](../src/sentinel/)) provides AI-assisted behavioral anomaly detection and automated disaster remediation while enforcing mathematically strict, deterministic policy constraints before any state modification is executed.

```
┌────────────────────────────────────────────────────────┐
│ 1. Behavioral Anomaly Engine (anomaly_engine.ts)       │
│    Monitors transaction velocity, schema mutations,    │
│    and out-of-order sequence deviations.               │
└───────────────────────────┬────────────────────────────┘
                            │ Incident Trigger
┌───────────────────────────▼────────────────────────────┐
│ 2. Autonomous Recovery Advisor (advisor.ts)            │
│    Drafts structured AdvisoryRecoveryProposal.         │
└───────────────────────────┬────────────────────────────┘
                            │ Evaluation Request
┌───────────────────────────▼────────────────────────────┐
│ 3. Deterministic Policy Gate (policy_gate.ts)          │
│    Strict Scope Bounding + Non-Speculative Hashes      │
│    + WORM Immutability Check + EVM Anchor Finality    │
│    + Blast Radius Cap + Atomic Pre-Approval TOCTOU     │
└───────────────────────────┬────────────────────────────┘
                            │ ALLOW_PROPOSAL
┌───────────────────────────▼────────────────────────────┐
│ 4. Execution Coordinator (coordinator.ts)              │
│    Replays verified mutations against basis state.     │
└────────────────────────────────────────────────────────┘
```

---

## 2. Six Mathematical Invariants of PolicyGate

`PolicyGate.evaluateProposal` in [`src/sentinel/policy_gate.ts`](../src/sentinel/policy_gate.ts) evaluates every proposal against 6 strict invariants:

### Invariant 1: Strict Scope Bounding
- Proposal's `protectedScope` must be in `registeredScopes`.
- Every record in `affectedRecords` must satisfy `matchesProtectedScope(record.tableName, proposal.protectedScope)` (supports exact table names and wildcard schemas like `public.*`).

### Invariant 2: Non-Speculative Changes Hash
- $\text{computedChangesHash} = \text{SHA-256}\big(\text{c14n}(\text{affectedRecords})\big)$.
- Must match `proposal.proposedChangesHash` using `timingSafeEqualHashes`.

### Invariant 3: Verifiable Basis & Store Immutability
- Basis checkpoint `sourceCheckpointId` must exist in `externalVaultStore`.
- Store MUST cryptographically verify its WORM integrity: `await externalVaultStore.verify(sourceCheckpointId) === true`.
- Basis checkpoint `merkleRoot` must match `proposal.expectedMerkleRoot`.

### Invariant 4: Finalized On-Chain EVM Anchor Check
- On-chain anchor for `sourceCheckpointId` must exist on the EVM adapter.
- Anchor status MUST be `FINALIZED` (with required block confirmations).
- Anchor `checkpointDigest` must match `proposal.expectedAnchorDigest`.

### Invariant 5: Blast Radius Cap
- The number of affected rows MUST NOT exceed `MAX_AUTONOMOUS_BLAST_RADIUS = 1000`.

### Invariant 6: Atomic Pre-Approval TOCTOU Defense
- Re-reads basis checkpoint from `externalVaultStore.get(sourceCheckpointId)` immediately prior to issuing approval and asserts digest and Merkle root equality.
- Re-reads anchor from `evmAnchorAdapter.getAnchor(sourceCheckpointId)` immediately prior to approval and asserts `FINALIZED` status and digest equality.
- Rejects immediately with `UNTRUSTED_RECOVERY_BASIS` or `ANCHOR_VERIFICATION_FAILED` if any value changed mid-evaluation.
