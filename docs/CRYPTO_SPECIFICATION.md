# WolverineDB // Cryptographic Specification

> **Source Code is Authoritative.**  
> This specification documents all cryptographic algorithms, hash domains, signature schemes, Merkle structures, and serialization standards used in **WolverineDB v1.3.0**.

---

## 1. Cryptographic Primitives

| Primitive | Algorithm | Purpose | Implementation Location |
| :--- | :--- | :--- | :--- |
| **Asymmetric Signatures** | Ed25519 (RFC 8032) | Customer commitment signing, validator attestations, recovery approvals | [`src/crypto/approval.ts`](../src/crypto/approval.ts) |
| **Cryptographic Hashing** | SHA-256 (FIPS 180-4) | Merkle trees, commitment digests, attestation digests, ledger hash-chains | [`src/crypto/hash.ts`](../src/crypto/hash.ts) |
| **Canonical Serialization** | Canonical JSON (c14n) | Non-malleable deterministic payload encoding | [`src/binary/c14n.ts`](../src/binary/c14n.ts) |
| **Constant-Time Compare** | `crypto.timingSafeEqual` | Side-channel resistant hash and digest comparison | [`src/crypto/hash.ts`](../src/crypto/hash.ts) |

---

## 2. Strict Domain Separation

To prevent cross-protocol collision attacks, all SHA-256 hashes MUST prepend a strict UTF-8 domain prefix before digesting payload buffers:

```ts
const DOMAIN_COMMITMENT  = Buffer.from('WDB:COMMITMENT:v1:', 'utf8');
const DOMAIN_TRUST       = Buffer.from('WDB:TRUST:v1:', 'utf8');
const DOMAIN_ATTESTATION = Buffer.from('WDB:ATTESTATION:v1:', 'utf8');
const DOMAIN_APPROVAL    = Buffer.from('WDB:APPROVAL:v1:', 'utf8');
const DOMAIN_MERKLE_LEAF = Buffer.from('WDB:MERKLE:LEAF:v1:', 'utf8');
const DOMAIN_MERKLE_NODE = Buffer.from('WDB:MERKLE:NODE:v1:', 'utf8');
```

### Commitment Digest Calculation ([`src/trust_network/commitment.ts`](../src/trust_network/commitment.ts)):
$$\text{Digest} = \text{SHA-256}\Big(\text{"WDB:TRUST:v1:"} \,\|\, \text{c14n}(\text{CommitmentBase})\Big)$$

---

## 3. Canonical JSON Encoding (`c14n`)

Deterministic state hashing requires identical byte representations regardless of object key order, whitespace, or floating-point formatting.

**Rules Enforced by `canonicalizeJson` in [`src/binary/c14n.ts`](../src/binary/c14n.ts)**:
1. Object keys are recursively sorted alphabetically in lexicographical order.
2. Zero whitespace between tokens (`:`, `,`).
3. `BigInt` values are serialized as explicit string integers.
4. `Buffer` objects are serialized as lowercase hexadecimal strings.
5. All strings are UTF-8 encoded with standard JSON escaping.

---

## 4. Merkle Tree State Root Construction

Database transactions within a commit window are aggregated into a deterministic balanced binary Merkle tree ([`src/crypto/merkle.ts`](../src/crypto/merkle.ts)):

1. **Leaf Hash**:
   $$\text{Leaf}_i = \text{SHA-256}\Big(\text{"WDB:MERKLE:LEAF:v1:"} \,\|\, \text{c14n}(\text{MutationTuple}_i)\Big)$$
2. **Internal Node Hash**:
   $$\text{Node}_{k} = \text{SHA-256}\Big(\text{"WDB:MERKLE:NODE:v1:"} \,\|\, \text{LeftChild} \,\|\, \text{RightChild}\Big)$$
3. **Odd Node Handling**: If a level has an odd number of nodes, the last node is duplicated to maintain balance.

---

## 5. Byzantine Quorum Certificate ($2f+1$)

A `QuorumCertificate` aggregates Ed25519 signatures from $N = 3f+1$ independent validators:

```ts
export interface QuorumCertificate {
  certificateId: string;
  commitmentId: string;
  epoch: number;
  validatorSetId: string;
  quorumThreshold: number;
  participatingValidators: string[];
  signatures: Buffer[]; // Ed25519 signatures
  certificateDigest: Buffer;
  finalizedAtUs: bigint;
}
```

**Verification Rule**:
An offline auditor verifies that:
1. `signatures.length >= quorumThreshold` (where $\text{threshold} \ge 2f+1$).
2. Each signature is cryptographically valid against the public key of the corresponding validator in `participatingValidators`.
3. `certificateDigest` matches $\text{SHA-256}(\text{"WDB:QC:v1:"} \,\|\, \text{c14n}(\text{CertificateFields}))$.
