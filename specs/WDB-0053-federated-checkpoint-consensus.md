# WDB-0053: Federated Multi-Node Checkpoint Consensus

Status: Normative Specification (v0.6 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the $M$-of-$N$ threshold consensus protocol over state checkpoints reported across multiple federated nodes.

## 2. Federated Consensus Protocol

When a checkpoint is created, participating database nodes submit signed Checkpoint Attestation records:

```typescript
export interface NodeCheckpointAttestation {
  nodeId: string;
  checkpointId: string;
  checkpointDigest: Buffer; // 32 bytes SHA-256
  commitSeq: bigint;
  merkleRoot: Buffer; // 32 bytes SHA-256
  timestampUs: bigint;
  signature: Buffer; // 64 bytes Ed25519 signature
}
```

## 3. Consensus Policies & Verdicts

```text
            Node A Attestation ─────┐
            Node B Attestation ─────┤
            Node C Attestation ─────┼──► [M-of-N Quorum Eval] ──► VERDICT
            Node D Attestation ─────┤
            Node E Attestation ─────┘
```

The Federated Consensus Engine evaluates attestations against policy $(M, N)$:
- $\ge M$ matching attestations from `TRUSTED` nodes $\implies$ `FEDERATION_CONSENSUS_VALID`.
- $\ge 1$ but $< M$ matching attestations $\implies$ `FEDERATION_CONSENSUS_DEGRADED`.
- 0 matching attestations or conflicting majorities $\implies$ `FEDERATION_CONSENSUS_DIVERGENCE`.

Any node submitting a divergent checkpoint is flagged for immediate quarantine (`WDB-0054`).
