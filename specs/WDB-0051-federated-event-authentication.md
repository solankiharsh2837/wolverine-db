# WDB-0051: Federated Event Authentication & Hash-Chaining

Status: Normative Specification (v0.6 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the cryptographic packaging and hash-chaining of security events across federated Wolverine nodes.

## 2. Authenticated Federated Event Envelope

Every event transmitted across nodes MUST be wrapped in an authenticated federated envelope:

```typescript
export interface FederatedEventEnvelope {
  event: SecurityEventEnvelope; // WDB-0041
  originNodeId: string;
  nodeSequence: bigint; // Monotonically increasing per node (1, 2, 3...)
  previousEventHash: Buffer; // 32 bytes SHA-256 of prior event from this node
  eventChainHash: Buffer; // 32 bytes SHA-256 over [previousHash || eventBytes]
  nodeSignature: Buffer; // 64 bytes Ed25519 signature over eventChainHash
}
```

## 3. Hash-Chained Verification Rules

```text
Node A:
  E_1 (seq: 1, prev: GENESIS_HASH) ──► E_2 (seq: 2, prev: H(E_1)) ──► E_3 (seq: 3, prev: H(E_2))
```

A receiving node MUST assert:
1. `nodeSequence == expectedLastSequence + 1n`.
2. `previousEventHash == lastKnownEventChainHash`.
3. `nodeSignature` is valid under `originNodeId`'s registered Ed25519 public key.
4. Origin node is currently in `TRUSTED` status (`WDB-0052`).

If any check fails, the event MUST be rejected and the node flagged for quarantine (`WDB-0054`).
