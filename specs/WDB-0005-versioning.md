# WDB-0005: Versioning

Status: Normative Specification (v0.1 Frozen).

## Version Record Structure

A Version record binds:
- `version_id` (UUID, 16 bytes)
- `parent_version_id` (UUID, 16 bytes)
- `transaction_id` (UTF8 string)
- `commit_timestamp` (TIMESTAMP_US, 8 bytes I64)
- `ordered_change_hashes` (Array of SHA256 hash bytes)
- `state_root` (SHA256, 32 bytes)
- `status` (U64: `1` = ACTIVE, `2` = SUPERSEDED, `3` = RECOVERED)

## Genesis Version Convention

- The genesis version (first version in a scope) has no real parent.
- `parent_version_id` MUST be set to the nil UUID (`00000000-0000-0000-0000-000000000000`).
- `parent_version_hash` for version hash calculation MUST be 32 zero bytes (`0x00` * 32).

## Linear Hierarchy & Immutability

Versions are strictly append-only. A corrective recovery action MUST create a new `RECOVERY` version (record type 6) referencing the incident and approval envelope. Prior versions, parent links, change hashes, state roots, and historical statuses MUST NOT be edited or overwritten. v0.1 enforces a single linear parent relation.
