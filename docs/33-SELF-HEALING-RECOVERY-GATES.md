# Policy-Gated Self-Healing Recovery

WolverineDB implements self-healing as a policy-gated, cryptographically verifiable recovery procedure rather than autonomous black-box automation.

## The 5-Step Self-Healing Pipeline

1. **Detection**: Integrity Verifier detects Merkle divergence or Sentinel flags critical behavioral anomaly.
2. **Advisory Proposal**: Sentinel Advisor analyzes historical checkpoints and external blockchain anchors to construct a bounded, non-destructive restoration proposal (`AdvisoryRecoveryProposal`).
3. **Policy Gate Evaluation**: Deterministic Policy Gate asserts:
   - Target basis state exists and matches external anchor digest.
   - Restorations are strictly bounded within authorized scope.
   - Proposed changes hash is cryptographically exact.
4. **Ed25519 Quorum Signing**: Multi-party approvers sign the verified proposal payload using Ed25519 keys.
5. **Atomic Execution & Re-Anchoring**: The recovery engine executes compensating mutations forward-additively, recalculates the Merkle root, emits a recovery provenance record, and anchors the new state to external stores.
