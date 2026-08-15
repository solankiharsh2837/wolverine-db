# WDB-0050: Node Cryptographic Identity Protocol

Status: Normative Specification (v0.6 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the cryptographic identity and registration protocol for individual Wolverine nodes across distributed deployments.

## 2. Node Identity Schema

Every node MUST have an immutable cryptographic identity:

```typescript
export type NodeCapability =
  | 'DATABASE_MUTATION_CAPTURE'
  | 'RUNTIME_EXECUTION_OBSERVER'
  | 'AEGIS_THREAT_ANALYTICS'
  | 'SENTINEL_ADVISORY_ENGINE'
  | 'POLICY_GATEKEEPER'
  | 'RECOVERY_EXECUTOR';

export interface NodeIdentity {
  nodeId: string; // "node:region-cluster-01:uuid"
  publicKey: Buffer; // 32 bytes Ed25519 public key
  capabilities: NodeCapability[];
  creationEpochUs: bigint;
  organizationId: string;
  clusterId: string;
  attestationSignature: Buffer; // 64 bytes Ed25519 signature over canonical registration
}
```

## 3. Node Attestation Signature

A node proves ownership of its identity by signing a canonical registration payload:

```
NodeAttestationDigest = SHA-256(
    "WDB:NODE_ID:v1:" ||
    node_id_len (2 bytes BE U16) || node_id_bytes ||
    public_key (32 bytes) ||
    creation_epoch_us (8 bytes BE I64) ||
    organization_id_bytes ||
    cluster_id_bytes
)
```
Nodes with invalid attestation signatures MUST be rejected upon registration.
