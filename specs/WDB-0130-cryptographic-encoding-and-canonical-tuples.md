# WDB-0130: Cryptographic Encoding and Canonical Protocol Tuples

**Status**: Normative (Frozen)  
**Version**: 1.3.0  
**Domain**: Cryptographic Serialization & Non-Malleability

---

## 1. Abstract

This specification defines the canonical binary serialization format for all multi-field preimages, signing statements, attestation digests, and identity commitments across WolverineDB. It eliminates all field boundary ambiguities by enforcing strict type tagging and explicit 4-byte big-endian length prefixing.

---

## 2. Canonical Tuple Wire Encoding

A canonical protocol tuple is serialized as:

$$\text{Tuple} = \text{DomainPrefix} \mathbin{\Vert} \text{Field}_1 \mathbin{\Vert} \text{Field}_2 \mathbin{\Vert} \dots \mathbin{\Vert} \text{Field}_k$$

Where each $\text{Field}_i$ is encoded with an unambiguous type header:

| Field Type | Type Tag | Length Header | Value Bytes |
| :--- | :--- | :--- | :--- |
| **String** | `0x01` (1 byte) | `u32be(len)` (4 bytes) | UTF-8 encoded bytes |
| **Buffer / Bytes** | `0x02` (1 byte) | `u32be(len)` (4 bytes) | Raw byte payload |
| **Int32 / UInt32** | `0x03` (1 byte) | — | 4 bytes Big-Endian |
| **BigInt (Int64/UInt64)** | `0x04` (1 byte) | — | 8 bytes Big-Endian |

---

## 3. Invariants

1. **Unambiguous Decodability**: For any two distinct semantic tuples $(A_1, \dots, A_n) \ne (B_1, \dots, B_m)$, their serialized representations must differ ($\text{Serialize}(A) \ne \text{Serialize}(B)$).
2. **Domain Separation**: Every protocol tuple must begin with an explicit versioned domain string (e.g. `WDB:ATTEST:v2:`, `WDB:APPROVAL_ENVELOPE:v2:`, `WDB:NODE_ID:v2:`).
