# WolverineDB Production Convergence & Trust State Machine Architecture

---

## 1. Single Authoritative Production Pipeline

WolverineDB v1.3.1 unifies the executable pipeline into a single linear workflow from live PostgreSQL mutation to offline proof verification:

```text
  ┌─────────────────────────────────────────────────────────────┐
  │                    CUSTOMER DATA PLANE                      │
  │                                                             │
  │  PostgreSQL Table ──> PL/pgSQL Trigger ──> Pending CDC Log │
  │                              │                              │
  │                              ▼                              │
  │                      PostgresAdapter                        │
  │                              │                              │
  │                              ▼                              │
  │                  validateChangeRecordData()                 │
  │                              │                              │
  │                              ▼                              │
  │                    WalNormalizer (c14n)                     │
  │                              │                              │
  │                              ▼                              │
  │                   CheckpointAnchorEngine                    │
  │                              │                              │
  │                              ▼                              │
  │               WolverineEvidenceAgentClient                  │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ (mTLS / Signed RPC)
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                   WOLVERINE TRUST NETWORK                   │
  │                                                             │
  │                     TrustGatewayServer                      │
  │             (Structured Peer Failure Telemetry)             │
  │                              │                              │
  │                              ▼                              │
  │               5 Byzantine Validator Daemons                 │
  │             (Crash-Safe Journal & Attestation)              │
  │                              │                              │
  │                              ▼                              │
  │                     TrustConsensusEngine                    │
  │                       (4-of-5 Quorum)                       │
  │                              │                              │
  │                              ▼                              │
  │                    PersistentTrustLedger                    │
  │                  (Serialized Mutex Queue)                   │
  │                              │                              │
  │                              ▼                              │
  │                   3 Ledger Replica Nodes                    │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                     INDEPENDENT TRUST                       │
  │                                                             │
  │                 Commercial Trust Receipt                    │
  │                              │                              │
  │                              ▼                              │
  │                 OfflineTrustProofVerifier                   │
  │               (Zero Network Calls / Air-Gapped)             │
  └─────────────────────────────────────────────────────────────┘
```

---

## 2. Node Trust State Machine

Nodes in the federation and validator cluster follow a strict, non-decorative state machine:

```text
                        ┌──────────────────┐
                        │    REGISTERED    │
                        └────────┬─────────┘
                                 │
                   ┌─────────────┴─────────────┐
         (No Private Key /             (Valid Private Key &
          No Signature)                 Correspondence Proved)
                   │                                   │
                   ▼                                   ▼
        ┌──────────────────┐               ┌──────────────────┐
        │    UNATTESTED    │               │     TRUSTED      │
        │ (Trust Denied)   │               │ (Cryptographic)  │
        └──────────────────┘               └────────┬─────────┘
                                                    │
                                      ┌─────────────┴─────────────┐
                              (Suspicious Activity)       (Key Compromise)
                                      │                           │
                                      ▼                           ▼
                           ┌──────────────────┐       ┌──────────────────┐
                           │   QUARANTINED    │       │     REVOKED      │
                           └──────────────────┘       └──────────────────┘
```

- **No Fake Zero Signatures**: A registered node without a valid Ed25519 attestation signature is marked `UNATTESTED`.
- **Pre-Commit Verification**: Node queries via `isNodeTrusted(nodeId)` evaluate both `status === 'TRUSTED'` and a bitwise cryptographic verification of the node identity signature.

---

## 3. Structured Failure Telemetry

The gateway records structured telemetry on every peer interaction failure:

```typescript
export interface PeerFailureRecord {
  peerId: string;
  endpoint: string;
  reason: 'TIMEOUT' | 'UNREACHABLE' | 'PEER_REJECTED' | 'MALFORMED_RESPONSE' | 'AUTH_FAILURE' | 'INTERNAL_ERROR';
  errorMessage: string;
  timestampUs: bigint;
}
```

Operators distinguish network partitions from Byzantine equivocation rejections without blind `catch {}` suppression.
