# WDB-0071: Reconstruction Proof Graph Protocol

Status: Normative Specification (v0.7.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the **Reconstruction Proof Graph** (`ReconstructionProofGraph`). The proof graph is a deterministic Directed Acyclic Graph (DAG) establishing complete proof paths from trusted basis checkpoints to individual mutation replay decisions.

## 2. Graph Node Schema

Every node in the Reconstruction Proof Graph represents a verified fact or mutation candidate:

```typescript
export interface ProofGraphNode {
  nodeId: string;
  type: 'CHECKPOINT' | 'MUTATION' | 'AUTHORIZATION' | 'PROVENANCE' | 'EXTERNAL_COMMITMENT';
  commitSeq: bigint;
  hash: Buffer; // 32-byte SHA-256
  parentIds: string[];
  proofData: Record<string, unknown>;
  evaluationStatus: 'VERIFIED' | 'FAILED' | 'UNVERIFIABLE';
}
```

## 3. Proof Path Invariant

A mutation node $N_{\text{mut}}$ has a **Complete Proof Path** if and only if:
1. $N_{\text{mut}}$ has an inbound edge from an authentic `AUTHORIZATION` node whose Ed25519 signature verifies against a registered key.
2. $N_{\text{mut}}$ has an inbound edge from an authentic `PROVENANCE` node linking execution to an uncompromised actor and approved ticket.
3. Either:
   a. $N_{\text{mut}}$ connects contiguously via hash chain to a verified `CHECKPOINT` node, OR
   b. $N_{\text{mut}}$ has an independent `EXTERNAL_COMMITMENT` node anchored to external trust storage.

## 4. Deterministic Graph Digest

The entire Reconstruction Proof Graph is canonicalized and hashed to produce a single 32-byte commitment:
$$\text{ReconstructionGraphDigest} = \text{SHA-256}(\text{"WDB:PROOF\_GRAPH:v1:"} \parallel \text{RFC8785\_Canonicalize}(\text{nodes, edges}))$$
