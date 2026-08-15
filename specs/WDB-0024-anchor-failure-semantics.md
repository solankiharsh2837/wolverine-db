# WDB-0024: Anchor Failure & Reorg Semantics

Status: Normative Specification (v0.3 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the formal failure semantics and deterministic handling of non-ideal external conditions (blockchain network reorgs, RPC failures, transaction stalls, orphan anchors, and contradictory external commitments).

## 2. Failure Scenarios & Deterministic Responses

| Scenario | Trigger / Root Cause | Deterministic Behavior | System Status |
| :--- | :--- | :--- | :--- |
| **RPC Unreachable** | External blockchain endpoint times out or returns HTTP 5xx | Buffer anchor in local pending queue; retry with exponential backoff | Core database operational; verification reports `ANCHOR_RPC_OFFLINE` |
| **Pending Transaction** | Transaction submitted to mempool, awaiting inclusion | Track in-flight tx hash; monitor block height until required depth | `PENDING_CONFIRMATION` |
| **Block Reorganization** | Block containing anchor tx is reorganized out below confirmation depth | Detect missing tx receipt in canonical chain; rebroadcast with fresh nonce | `REORG_DETECTED_REBROADCASTING` |
| **Conflicting Anchor** | External anchor exists with identical ID but differing digest | Treat as hostile tampering attempt; fail closed immediately | `CONFLICTING_ANCHOR_REJECTED` |
| **Orphan Anchor** | Anchor exists on-chain for a checkpoint deleted from local DB | Verifier flags missing local state version | `ORPHAN_ANCHOR_DETECTED` |
| **Gas Price Spike** | Network base fee exceeds configured `max_gas_price_gwei` | Pause broadcast until gas price normalizes or admin overrides | `ANCHOR_GAS_SUSPENDED` |

## 3. Fail-Closed Invariants

- An external anchor outage MUST NOT corrupt or halt live transactional processing in PostgreSQL/MySQL/SQLite.
- An anchor outage MUST be transparently surfaced during verification, preventing unanchored states from being falsely certified as externally proven.
