# WDB-0006: Recovery

Status: Normative Specification (v0.1 Frozen).

## Recovery Proposal

A recovery proposal MUST include:
- `incident_id` (UUID, 16 bytes)
- `protected_scope` (UTF8 string)
- `trusted_basis_version_id` (UUID, 16 bytes)
- `proposed_changes_hash` (SHA256, 32 bytes)
- `requester_id` (UTF8 string)
- `policy_result` (UTF8 string / status)

Proposal generation is strictly non-destructive.

## Cryptographic Policy Approval Envelope

Execution of a recovery proposal MUST require a policy-valid `ApprovalEnvelope`. The canonical binary payload to be signed is:
`incident_id (16 bytes) || protected_scope (UTF8) || target_version_id (16 bytes) || proposed_changes_hash (32 bytes) || requester_id (UTF8) || approver_pubkey (32 bytes) || nonce (16 bytes) || expires_at (8 bytes I64 TIMESTAMP_US)`

The signature field is a 64-byte Ed25519 signature over the canonical byte stream above.

## Approval Validation Rules

The Recovery Engine MUST validate all of the following rules before executing a recovery transaction:
1. **Signature Verification**: `signature` MUST verify using `approver_pubkey` over the canonical envelope bytes.
2. **Key Authority**: `approver_pubkey` MUST exist in the configured trusted approval public key set (`authorization.trusted_approvers`).
3. **Separation of Duties**: `approver_pubkey` MUST NOT correspond to `requester_id`.
4. **Scope & Proposal Binding**: `incident_id`, `protected_scope`, `target_version_id`, and `proposed_changes_hash` MUST match the recovery proposal exactly.
5. **Expiration Check**: `expires_at` MUST be in the future relative to the current UTC execution timestamp.
6. **Replay Protection**: `nonce` (UUID v4) MUST NOT match any previously recorded approval nonce in `wolverine_sys.approval_nonces`.

If any condition fails, execution MUST be aborted and an authorization error (`WDB6xx`) returned.

## Execution Dynamics

Recovery execution runs as a normal protected transaction emitting normal `CHANGE` records plus a `RECOVERY` record referencing the incident and signed approval. All original compromised values and evidence remain preserved in immutable history. If trust cannot be established, WolverineDB MUST return an `INDETERMINATE` status.
