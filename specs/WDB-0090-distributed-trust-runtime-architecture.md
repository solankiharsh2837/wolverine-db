# WDB-0090: Distributed Trust Runtime Architecture Protocol

Status: Normative Specification (v0.9.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the **Distributed Trust Network Runtime** for WolverineDB v0.9.0. It defines the physical network topology, transport bindings, process boundaries, and failure domains for deploying the Wolverine Trust Network as an actual distributed cluster of independent daemons.

## 2. Distributed Process Topology

```text
                  CUSTOMER ENVIRONMENT
                 ┌────────────────────────────────┐
                 │ PostgreSQL / MySQL / SQLite    │
                 │              │ (CDC / WAL)     │
                 │              ▼                 │
                 │ Wolverine Evidence Agent       │
                 └──────────────┬─────────────────┘
                                │ (HTTP / mTLS Transport)
                                ▼
                 ┌────────────────────────────────┐
                 │ TRUST GATEWAY CLUSTER          │
                 │ - Tenant Authentication        │
                 │ - Rate Limiting & Quota        │
                 │ - Broadcast & Coordination     │
                 └──────────────┬─────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│ Validator #01 │       │ Validator #02 │  ...  │ Validator #05 │
│ (Daemon Node) │       │ (Daemon Node) │       │ (Daemon Node) │
└───────┬───────┘       └───────┬───────┘       └───────┬───────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │ (Validator Attestations)
                                ▼
                 ┌────────────────────────────────┐
                 │ QUORUM CONSENSUS ENGINE        │
                 │ - Threshold M-of-N Assembly    │
                 │ - Quorum Certificate Issuance  │
                 └──────────────┬─────────────────┘
                                │ (Finalized Records)
                                ▼
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│ Ledger Primary│       │ Ledger Backup │       │ Ledger Replica│
│ (State Mach.) │       │ (Replication) │       │ (Audit Store) │
└───────────────┘       └───────────────┘       └───────────────┘
```

## 3. Physical Process Independence

- Every `ValidatorNode` **MUST** run in an isolated process with its own private Ed25519 key store in memory/HSM.
- The `TrustGateway` **MUST NOT** possess validator private keys or customer private keys.
- `LedgerReplica` nodes **MUST** independently verify record hash chains before committing them to persistent storage.
