# WDB-0112: Malicious Primary Replica Defense Protocol

Status: Normative Specification (v1.1.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes replica defense against a rogue primary ledger node attempting to broadcast fabricated records or divergent Merkle state roots.

## 2. Replica Verification Rules

Before accepting any `REPLICATE_RECORD` RPC from the primary:
1. **Quorum Certificate Verification**: The replica MUST verify that the record payload contains a valid `QuorumCertificate` with $\ge M$ valid signatures from registered validator public keys.
2. **Sequential Hash Continuity**: The replica MUST verify $P_i = \text{hash}(R_{i-1})$ and $S_i = S_{i-1} + 1$.
3. **State Root Recalculation**: The replica MUST independently compute the incremental Merkle state root. If the primary's claimed root diverges from the replica's computed root, the replica MUST reject the record, issue a `PRIMARY_EQUIVOCATION_ALERT`, and halt replication.
