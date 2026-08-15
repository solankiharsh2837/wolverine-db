# WDB-0055: Federated Multi-Node Recovery Authorization

Status: Normative Specification (v0.6 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the federated extension of multi-party recovery authorization (`WDB-0006`, `WDB-0013`), requiring multi-node quorum signatures across independent node identities before executing selective state recovery.

## 2. Federated Quorum Rules

A federated deployment configures a quorum policy $(K, N)$ requiring $K$ distinct valid signatures from approved nodes or designated security authorities:

```text
               Recovery Proposal (RP-000184)
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
     Node A Signature  Node B Signature  Security Authority
            │                │                │
            └────────────────┼────────────────┘
                             ▼
                    FEDERATED QUORUM
                     (e.g. 2-of-3)
                             │
                             ▼
                     RECOVERY ENGINE
```

### 2.1 Separation of Duties
1. The proposing node (`originNodeId`) **MUST NOT** count toward the required approval quorum $K$.
2. Nodes currently in `QUARANTINED` or `REVOKED` status **MUST NOT** sign recovery envelopes.
3. Every signature MUST verify against the node's registered Ed25519 identity key.
