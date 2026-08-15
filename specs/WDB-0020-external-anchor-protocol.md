# WDB-0020: External Anchor Protocol

Status: Normative Specification (v0.3 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the cryptographic protocol for anchoring WolverineDB state commitments to external, decentralized, or third-party trust domains (e.g. Ethereum, EVM L2s, Bitcoin, public timestamping registries).

## 2. Invariant: Off-Chain Evidence, On-Chain Commitment

WolverineDB **MUST NOT** store row data, transactions, or internal database metadata on public blockchains. An anchor record consists strictly of a compact 32-byte cryptographic commitment binding a specific historical Checkpoint Digest (`WDB-0012`).

```
Canonical Checkpoint
        │
        ▼
 Checkpoint Digest (32 bytes SHA-256)
        │
        ▼
   Anchor Engine
        │
        ▼
Canonical Anchor Commitment
(WDB:ANCHOR:v1:<domain_id>:<checkpoint_id>:<digest>)
        │
        ▼
 Public Trust Domain
```

## 3. Canonical Anchor Commitment Payload

The canonical byte sequence for an anchor payload MUST be computed using domain-separated SHA-256:

```
AnchorPayloadDigest = SHA-256(
    "WDB:ANCHOR:v1:" ||
    domain_type (2 bytes BE U16) ||
    chain_id_len (2 bytes BE U16) || chain_id_bytes (UTF-8) ||
    checkpoint_id (16 bytes UUID) ||
    checkpoint_digest (32 bytes SHA-256) ||
    commit_seq (8 bytes BE I64) ||
    timestamp_us (8 bytes BE I64)
)
```

### 3.1 Domain Types
Numeric values for public trust domain types:
- `1`: `EVM` (Ethereum Mainnet, Arbitrum, Optimism, Base, Polygon)
- `2`: `BITCOIN_OP_RETURN`
- `3`: `RFC6962_TRANSPARENCY_LOG`
- `4`: `RFC3161_TIMESTAMP_AUTHORITY`

## 4. Anchor Lifecycle States

An anchor record tracks through the following discrete lifecycle states:
1. `PENDING`: Transaction constructed and broadcast to the trust domain; awaiting inclusion.
2. `CONFIRMING`: Transaction included in a block; awaiting target confirmation depth.
3. `FINALIZED`: Transaction buried past reorg depth threshold; cryptographically anchored.
4. `ORPHANED_REORG`: Block containing transaction was reorganized out; retry required.
5. `FAILED`: Transaction dropped, out-of-gas, or permanently rejected.

## 5. Security & Verification Requirements

- An external anchor is valid if and only if the on-chain recorded `checkpoint_digest` matches the local checkpoint digest calculated under `WDB-0012` bit-for-bit.
- Any discrepancy between on-chain digest and local database state MUST be reported as a cross-domain integrity divergence (`CROSS_DOMAIN_DIVERGENCE`).
