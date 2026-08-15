# WDB-0123: Self-Contained Trust Receipt and Receipt Chain Protocol

Status: Normative Specification (v1.2.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the **Self-Contained Trust Receipt** schema and the **Receipt Chain** data structure connecting sequential trust receipts into an unbroken, tamper-evident cryptographic history.

## 2. Receipt Chain Linking Invariant

Each receipt $T_i$ MUST contain:
- `previousReceiptDigest`: SHA-256 digest of receipt $T_{i-1}$ (or zero hash for genesis).
- `currentCommitmentDigest`: Domain-separated hash of the customer commitment.
- `ledgerSeq`: Monotonic Trust Time sequence number.
- `epoch`: Network consensus epoch.
- `validatorSetDigest`: Merkle root / SHA-256 of all active validator public keys.

## 3. Receipt Chain Verification Algorithms

A `ReceiptChain` implementation MUST support:
- `verifyChain()`: Verifies full cryptographic continuity from Genesis to Head.
- `detectGap()`: Flags if sequence numbers skip ($S_i \ne S_{i-1} + 1$).
- `detectFork()`: Flags if two distinct receipts claim the same sequence number with different digests.
- `detectReplay()`: Flags duplicated historical receipts.
- `detectRollback()`: Flags if chain head points to an earlier sequence.
- `findLastVerifiedReceipt()`: Returns the highest contiguous valid receipt frontier.
