# WDB-0094: Dual-Timeline Trust Time Protocol

Status: Normative Specification (v0.9.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the **Dual-Timeline** temporal integrity model in WolverineDB.

## 2. Database Time vs. Trust Time

WolverineDB decouples internal database sequence progression from external network consensus progression:

$$\begin{aligned}
\text{Database Time: } & T_{\text{DB}} = (\text{databaseId}, \text{commitSeq}) \\
\text{Trust Time: } & T_{\text{Trust}} = (\text{epoch}, \text{ledgerSeq}, \text{quorumTimestampUs})
\end{aligned}$$

```text
DATABASE TIME (Local Mutation Progression)
     │
     │ commitSeq
     ▼
1842 ──────────────────────────────────────────► 1917


TRUST TIME (Wolverine Network Consensus Progression)
     │
     │ ledgerSeq
     ▼
8271 ──────────────────────────────────────────► 8420
```

## 3. Cryptographic Cross-Timeline Binding Invariant

Every finalized trust record forms an immutable cryptographic bridge:

$$\text{Bridge}(\text{Checkpoint}_{\text{commitSeq}=1842}) \Longleftrightarrow \text{LedgerRecord}_{\text{ledgerSeq}=8271}$$

An auditor can mathematically prove:
> *"Database checkpoint 1842 (digest `ABC...`) was finalized by quorum in the Wolverine Trust Network at or before Trust Sequence 8271 in Epoch 27."*
