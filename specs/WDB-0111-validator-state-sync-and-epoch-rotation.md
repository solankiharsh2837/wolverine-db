# WDB-0111: Validator State Sync and Epoch Rotation Protocol

Status: Normative Specification (v1.1.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details validator crash recovery, state catch-up sync, and epoch boundary advancement.

## 2. Catch-up State Sync

- When a validator crashes and restarts with stale sequence $S_{\text{local}} < S_{\text{network}}$:
  1. It connects to peer validator RPC endpoints `/rpc/sync?fromSeq=S_local+1`.
  2. It verifies the sequential hash chain and quorum certificates for each missing block before re-entering active consensus attestation.
  3. Stale attestations submitted for past epochs ($E_{\text{commit}} < E_{\text{current}}$) MUST be rejected with `STALE_EPOCH`.

## 3. Epoch Rotation Semantics

- Epoch transitions increment `epoch = epoch + 1` and commit an `EPOCH_CHANGE` record to the persistent ledger.
- During a transition grace period, commitments generated in $E$ MAY be finalized in $E+1$ provided the validator set hash is verified.
