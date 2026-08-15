# WDB-0126: Customer Disaster Queue and SLA Status Protocol

Status: Normative Specification (v1.2.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Customer Database Non-Blocking Invariant

Wolverine Trust Network availability MUST NOT block or halt live customer database transactions.
During an outage, network partition, or cluster loss:
- The customer Evidence Agent automatically transitions into **Durable Local Queue Mode**.
- Mutations continue committing locally to PostgreSQL / SQLite.
- The Agent persists signed commitments to disk.
- When Wolverine Trust Network connectivity is restored, queued commitments are replayed in monotonic sequence order.

## 2. Machine-Readable SLA Status Model

The Agent and Gateway expose real-time status:

```json
{
  "trustStatus": "TRUST_CURRENT",
  "lastFinalizedDatabaseSeq": "1842",
  "latestObservedDatabaseSeq": "1851",
  "pendingCommitments": 9,
  "lastFinalizedTrustSeq": "39182",
  "currentEpoch": 17,
  "validatorQuorum": "4/5",
  "ledgerHealth": "HEALTHY"
}
```

States: `TRUST_CURRENT`, `TRUST_DEGRADED`, `TRUST_PENDING`, `TRUST_OUTAGE`.
