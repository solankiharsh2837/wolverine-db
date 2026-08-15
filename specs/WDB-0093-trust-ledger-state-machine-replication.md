# WDB-0093: Trust Ledger State Machine Replication Protocol

Status: Normative Specification (v0.9.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details state machine replication across a cluster of `TrustLedgerReplicaNode` daemons.

## 2. Replication Model

- **Primary Node**: Appends finalized `FINALIZATION` records to the local ledger and broadcasts `REPLICATE_RECORD` messages to backup replicas.
- **Replica Nodes**: Receive records, verify sequence continuity ($S_i = S_{i-1} + 1$) and hash binding ($P_i = \text{hash}(R_{i-1})$), append to local ledger, and acknowledge back to the primary.
- **Catchup Synchronization**: If a replica detects a gap ($S_{\text{incoming}} > S_{\text{local}} + 1$), it issues `SYNC_REQUEST(fromSeq=S_local + 1)` and streams missing records before accepting new writes.
