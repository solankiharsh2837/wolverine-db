# WDB-0121: Crash-Safe Validator Persistence Journal Protocol

Status: Normative Specification (v1.2.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the crash-safe append-only journal schema, atomic flush semantics, and startup integrity recovery for standalone validator nodes.

## 2. Validator Journal Record Schema

Every journal record MUST commit to:

$$\begin{aligned}
\text{JournalRecordDigest} = \text{SHA256}( & \text{validatorId} \parallel \text{epoch} \parallel \text{ledgerSeq} \parallel \\
& \text{commitmentDigest} \parallel \text{previousLedgerDigest} \parallel \\
& \text{attestationDigest} \parallel \text{stateRoot} \parallel \\
& \text{validatorSetDigest} \parallel \text{timestampUs} \parallel \text{prevRecordDigest} )
\end{aligned}$$

## 3. Recovery and Fail-Closed Invariants

On startup or crash recovery:
- The journal MUST verify sequential record continuity from genesis ($S_1, S_2, \dots, S_n$).
- **Truncated Tail**: If the final record is torn / partially written due to power loss, the journal MAY truncate the uncommitted tail up to the last fully verified record.
- **Corrupted Intermediate Record**: If any intermediate record has a digest mismatch or torn bytes, the validator MUST enter `FAIL_CLOSED_CORRUPTED` and refuse all attestations.
- **Fork Detection**: If an incoming commitment or peer sync presents a conflicting hash for an already-attested sequence, the validator MUST halt and generate slashing evidence.
