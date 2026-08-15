# Validator & Replica Clusters Architecture

This document describes how validator daemons and ledger replicas communicate across failure boundaries.

## Cluster Protocol Flow
1. **Gateway Dispatch**: Gateway forwards a `TrustCommitment` in parallel to all validator daemon socket endpoints (`/rpc/attest`).
2. **Independent Attestation**: Each validator independently evaluates the commitment and returns a signed `ValidatorAttestation`.
3. **Quorum Assembly**: The Gateway consensus engine verifies that $\ge M$ valid signatures are present.
4. **Replica Sync**: The `FINALIZATION` record is pushed to all `TrustLedgerReplicaNode` instances, which verify hash continuity before writing to disk.
