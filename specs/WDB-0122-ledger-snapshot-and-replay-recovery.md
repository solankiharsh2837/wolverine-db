# WDB-0122: Ledger Snapshot and Replay Recovery Protocol

Status: Normative Specification (v1.2.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details deterministic state recovery from persistent snapshot checkpoints combined with incremental journal replays.

## 2. Recovery Calculation

Given a snapshot $K$ at sequence $S_k$ with hash $H_k$, and a journal suffix $J = \{R_{k+1}, \dots, R_m\}$:

1. **Snapshot Verification**: Compute `snapshotDigest` and verify signature from authoritative validator set.
2. **Sequential Replay**: For each record $R_i$ from $S_{k+1}$ to $S_m$:
   - Verify predecessor link $P_i = H_{i-1}$.
   - Verify `QuorumCertificate` has $\ge M$ valid validator signatures.
   - Update running Merkle state tree.
3. **Reconstructed Output**: Compute `reconstructedStateRoot`, `reconstructedLedgerDigest`, and `recoveryProofDigest`.

## 3. Strict Refusal Rules

Recovery MUST abort with error if:
- Snapshot digest does not match its internal cryptographic payload.
- Any journal record has a broken sequence gap or invalid quorum certificate.
- Two conflicting finalized histories exist at any sequence.
