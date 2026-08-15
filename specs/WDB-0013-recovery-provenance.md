# WDB-0013: Recovery Provenance

Status: Normative Specification (v0.2 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes recovery operations as a first-class, cryptographically bound provenance chain. In WolverineDB v0.2, recovery is not merely an out-of-band corrective action, but an immutable audit trail linking the initial incident, proposal, cryptographic approval, execution, and subsequent post-recovery state checkpoint.

## 2. Recovery Provenance Lifecycle

Every recovery action MUST follow the deterministic 6-stage provenance lifecycle:

```
INCIDENT (WDB-0001: RecordType 5)
    │
    ▼
VERIFICATION FAILURE / TRIAGE
    │
    ▼
RECOVERY PROPOSAL (WDB-0006)
    │
    ▼
APPROVAL ENVELOPE (Ed25519 Signed)
    │
    ▼
RECOVERY EXECUTION (Transaction Boundary)
    │
    ▼
POST-RECOVERY CHECKPOINT (Anchored Externally)
```

## 3. Provenance Linking Rules

1. **Incident Binding**: The recovery proposal MUST reference the unique `incident_id` generated during the integrity verification failure.
2. **Approval Binding**: The execution transaction MUST record the full, signed `ApprovalEnvelope` in `wolverine_sys.recoveries`.
3. **Change Attribution**: All compensating `CHANGE` records emitted during recovery MUST include the `incident_id` and `recovery_id` in their `provenance` metadata.
4. **Immediate Checkpoint Anchor**: Immediately following successful execution of a recovery transaction, the engine MUST emit a `POST_RECOVERY` Checkpoint and anchor it to the configured external `CheckpointStore`.
5. **No History Overwrite**: Compromised or invalid historical change records MUST NEVER be truncated or modified; recovery is strictly forward-additive.

## 4. Verification of Recovery Chains

When auditing a recovery event, the verifier MUST validate:
- The Ed25519 signature of the approver against configured trusted authority keys.
- That the requester and approver identities are strictly distinct (Separation of Duties).
- That the replay protection nonce has never been used in any other recovery.
- That the post-recovery checkpoint root deterministically links back to the pre-incident trusted basis state plus the applied corrective changes.
