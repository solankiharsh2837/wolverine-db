# WolverineDB // Continuous State Reconstruction & Disaster Survivability

> **Source Code is Authoritative.**  
> This specification documents the continuous verified state reconstruction engine, transaction dependency safety graphs, disaster queues, and crash-safe journals in **WolverineDB v1.3.0**.

---

## 1. Continuous State Reconstruction Architecture

Continuous reconstruction ([`src/continuous_reconstruction/`](../src/continuous_reconstruction/)) allows WolverineDB to reconstruct verified database states at arbitrary points in time while identifying and surgically excising compromised or malicious transactions.

```
┌─────────────────────────────────────────────────────────────┐
│ 1. State Frontier (src/reconstruction/frontier.ts)          │
│    Tracks latest verified commitSeq and checkpoint baseline.│
└──────────────────────────────┬──────────────────────────────┘
                               │ Verified Basis
┌──────────────────────────────▼──────────────────────────────┐
│ 2. Dependency Graph (src/continuous_reconstruction/         │
│    dependency_graph.ts)                                     │
│    Maps transaction causal dependencies (FKs, row updates). │
└──────────────────────────────┬──────────────────────────────┘
                               │ Safe Transaction Sequence
┌──────────────────────────────▼──────────────────────────────┐
│ 3. Replay Engine (src/reconstruction/replay_engine.ts)      │
│    Applies verified mutations in strict deterministic order.│
└──────────────────────────────┬──────────────────────────────┘
                               │ Reconstructed State
┌──────────────────────────────▼──────────────────────────────┐
│ 4. Provenance Verifier (src/engine/recovery_provenance.ts)   │
│    Validates cryptographic proof graph & approval nonces.   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Dependency Safety Graph

Implemented in [`src/continuous_reconstruction/dependency_graph.ts`](../src/continuous_reconstruction/dependency_graph.ts):
- **Causal Tracking**: Records read-after-write and foreign-key dependencies across transaction boundaries.
- **Taint Propagation**: If transaction $T_{\text{bad}}$ is flagged by the Sentinel anomaly detector, all downstream transactions $T_{\text{child}}$ that depend on rows modified by $T_{\text{bad}}$ are marked as tainted.
- **Surgical Extraction**: Allows the recovery engine to roll back $T_{\text{bad}}$ and its dependent subtree while preserving independent concurrent transactions.

---

## 3. Disaster Survivability & Crash-Safe Journals

Implemented in [`src/survivability/`](../src/survivability/):
1. **Crash-Safe Persistence Journal ([`crash_safe_journal.ts`](../src/survivability/crash_safe_journal.ts))**:
   - Write-ahead append-only journal with CRC32 checksums for every record.
   - Truncates incomplete/corrupted trailing writes upon process restart.
2. **Customer SLA & Outage Queue ([`customer_sla_manager.ts`](../src/survivability/customer_sla_manager.ts))**:
   - Queues commitments during network partitions or validator cluster outages.
   - Drains queue in strict sequence order upon reconnection.
3. **Byzantine State Proofs ([`byzantine_state_proof.ts`](../src/survivability/byzantine_state_proof.ts))**:
   - Generates compact zero-knowledge-style proofs of state correctness over long transaction chains.
