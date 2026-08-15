# WDB-0086: Trust Network Failure and Equivocation Semantics

Status: Normative Specification (v0.8.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes fail-closed behaviors, equivocation detection, and adversarial resilience across the Wolverine Trust Network.

## 2. Failure Taxonomy & Handling

| Condition | Cause | Network Response |
| :--- | :--- | :--- |
| `TRUST_EQUIVOCATION` | Two conflicting digests submitted for same `(tenantId, databaseId, commitSeq)`. | **Reject & Halt**: Record equivocation; do not finalize either commitment. |
| `CONSENSUS_UNAVAILABLE` | Fewer than $M$ validators respond within timeout window. | **Pending**: Retry broadcast; reject finalization until quorum met. |
| `VALIDATOR_COMPROMISED` | Single validator produces forged signature or corrupt digest. | **Quorum Isolation**: Dropped by consensus engine; requires $M$ honest validators. |
| `LEDGER_FORK_DETECTED` | Two different record digests for same `ledgerSeq`. | **Ledger Halt**: Refuse new appends; emit cryptographic audit alarm. |
| `OUTAGE_OFFLINE` | Wolverine API / Network unreachable from customer agent. | **Local Queueing**: Customer DB continues running uninterrupted; commitments queued locally. |
| `EXTERNAL_TRUST_DIVERGENCE` | Trust proof digest diverges from local WDB or WORM vault checkpoint. | **Reconstruction Block**: Reject automatic recovery; trigger incident response. |

## 3. Strict Fail-Closed Guarantee

Under no circumstance shall the Trust Network "guess", "vote by coin flip", or "pick the latest timestamp" when faced with equivocal commitments or ledger forks.
