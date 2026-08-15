# WDB-0023: Multi-Anchor Consensus Protocol

Status: Normative Specification (v0.3 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the multi-anchor consensus protocol in WolverineDB v0.3. Rather than relying on a single public anchor or external vault, WolverineDB aggregates commitments across $N$ heterogeneous independent trust domains (e.g. S3 WORM, Ethereum Mainnet, Base, Bitcoin timestamp) and evaluates cryptographic consensus under configurable $M$-of-$N$ threshold policies.

## 2. Anchor Topology & Consensus Engine

```
                          CHECKPOINT #42
                                │
        ┌───────────────┬───────┴───────┬───────────────┐
        ▼               ▼               ▼               ▼
    S3 / WORM       Ethereum          Base           Bitcoin
      Vault          Anchor          Anchor          Anchor
        │               │               │               │
        └───────────────┼───────────────┼───────────────┘
                        ▼               ▼
                        MULTI-ANCHOR CONSENSUS
                                │
                       [M-of-N Quorum Eval]
                                │
                        CONSENSUS VERDICT
```

## 3. Threshold Consensus Policies

A deployment configures a consensus policy defining required quorum $M$ out of total active anchors $N$:

```typescript
export interface ConsensusPolicy {
  requiredQuorum: number; // M
  totalAnchors: number;   // N
  minimumFinalizedAnchors: number;
}
```

### 3.1 Consensus Verdict States
1. **`CONSENSUS_VALID`**: $\ge M$ independent anchors agree with the local database Checkpoint Digest bit-for-bit.
2. **`CONSENSUS_SUSPICIOUS`**: At least one anchor matches, but total matching anchors $< M$ (minority confirmation or partial outage).
3. **`CONSENSUS_DIVERGENCE`**: Zero anchors match local database state, or multiple anchors disagree on historical commitments.
4. **`CONSENSUS_INDETERMINATE`**: Sufficient anchors are offline or unreachable, precluding quorum evaluation.

## 4. Byzantine Fault Resilience

1. **Independent Key / Identity Domains**: Anchors MUST be published using distinct network routes, keypairs, or credential sets to prevent single-compromise collapse.
2. **Weighted Votes**: Where configured, anchors MAY be assigned discrete cryptographic weights reflecting their underlying network security (e.g., L1 Ethereum weight = 2, local vault weight = 1).
