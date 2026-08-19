# WolverineDB // Byzantine Fault Tolerant Consensus Specification

> **Source Code is Authoritative.**  
> This specification documents the Byzantine quorum consensus engine, validator cluster coordination, attestation generation, and quorum certificates in **WolverineDB v1.3.0**.

---

## 1. Consensus Model & Quorum Mathematics

The Wolverine Trust Network operates a Byzantine Fault Tolerant (BFT) consensus protocol over database commit sequence milestones.

### Quorum Parameters:
- **Total Validators ($N$)**: Typically $N = 3f + 1$ (e.g., $N = 4$ for $f = 1$, $N = 7$ for $f = 2$, $N = 5$ for $f = 1$).
- **Byzantine Fault Tolerance ($f$)**: Maximum number of arbitrarily faulty, malicious, or offline validator nodes.
- **Quorum Threshold ($Q$)**: Minimum matching validator attestations required:
  $$Q = 2f + 1$$
- **Safety Theorem**:
  For any two valid quorums $Q_1, Q_2 \subseteq N$, their intersection satisfies:
  $$|Q_1 \cap Q_2| = |Q_1| + |Q_2| - |Q_1 \cup Q_2| \ge (2f + 1) + (2f + 1) - (3f + 1) = f + 1$$
  Since at most $f$ nodes are Byzantine, at least $(f+1) - f = 1$ honest validator exists in the intersection, guaranteeing that conflicting state sequences cannot achieve quorum.

---

## 2. Validator Node Architecture

Implemented in [`src/trust_network/validator.ts`](../src/trust_network/validator.ts):
1. **Commitment Verification**:
   - Verifies customer Ed25519 signature against registered customer public key.
   - Verifies commitment sequence monotonicity: `commitment.commitSeq > lastFinalizedSeq`.
   - Validates temporal ordering and checkpoint digest.
2. **Attestation Issuance**:
   - Signs the canonical attestation digest:
     $$\text{AttestationDigest} = \text{SHA-256}\Big(\text{"WDB:ATTESTATION:v1:"} \,\|\, \text{c14n}(\text{AttestationFields})\Big)$$
   - Returns a `ValidatorAttestation` containing validator ID, signature, and timestamp.

---

## 3. Consensus Engine & Ledger Binding

Implemented in [`src/trust_network/consensus.ts`](../src/trust_network/consensus.ts):
1. Aggregates attestations received from the validator cluster.
2. Filters invalid, forged, or duplicate validator signatures.
3. If valid attestations $\ge Q$:
   - Constructs a `QuorumCertificate`.
   - Appends a `FINALIZATION` entry to `WolverineTrustLedger`.
   - Returns both `{ certificate, ledgerRecord }` via `processAttestationsWithRecord` to enforce strict cryptographic binding at the Trust Gateway boundary.
