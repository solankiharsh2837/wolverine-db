# WDB-0120: Trust Network Durability and Health Model

Status: Normative Specification (v1.2.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the **Durability and Health State Model** of the Wolverine Trust Network. It defines the formal operational states, state transition rules, and independent health evaluation criteria.

## 2. Durability State Machine

```text
               ┌────────────────┐
               │    HEALTHY     │
               └───────┬────────┘
                       │ (Minor validator latency / loss < f)
                       ▼
               ┌────────────────┐
               │    DEGRADED    │
               └───────┬────────┘
                       │ (Loss >= f+1 OR Network Split)
                       ▼
        ┌──────────────┴──────────────┐
        ▼                             ▼
┌───────────────┐             ┌───────────────┐
│  PARTITIONED  │             │  QUORUM_LOST  │
└───────┬───────┘             └───────┬───────┘
        │                             │
        └──────────────┬──────────────┘
                       ▼
        ┌─────────────────────────────┐
        │  CATASTROPHIC_PARTIAL_LOSS  │
        └──────────────┬──────────────┘
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
┌───────────────┐             ┌───────────────┐
│LEDGER_RECOVERY│             │VALID_RECOVERY │
└───────┬───────┘             └───────┬───────┘
        │                             │
        └──────────────┬──────────────┘
                       ▼
               ┌────────────────┐
               │EPOCH_TRANSITION│
               └───────┬────────┘
                       ▼
               ┌────────────────┐
               │   RECOVERED    │
               └────────────────┘
```

## 3. Explicit Health Evaluation Invariant

The `TrustNetworkHealthEvaluator` MUST compute health by verifying:
1. **Validator Availability**: Count of active responsive validator daemons ($A \ge M$).
2. **Journal Continuity**: Monotonic sequence and hash continuity of local journals.
3. **Quorum Availability**: Verified ability to assemble $M$-of-$N$ threshold signatures.
4. **Replica State-Root Agreement**: Consensus across all replica Merkle roots ($\text{root}_1 = \text{root}_2 = \dots = \text{root}_k$).
5. **Epoch Agreement**: Synchronized network epoch across active nodes.
6. **Ledger Sequence Continuity**: Unbroken chain sequence from genesis ($S_1, S_2, \dots, S_n$).
7. **Storage Integrity**: CRC/SHA256 validation of on-disk journals.
