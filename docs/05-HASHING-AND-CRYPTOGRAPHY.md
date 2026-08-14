# Hashing and cryptography

v0.1 uses SHA-256 for integrity hash chains and Merkle trees, and Ed25519 for policy approval signatures.

All hashes use length-delimited inputs and strict domain separation:

- **Change Hash**: `SHA256("WDB:CHANGE:v1" || u32be(len(record_bytes)) || record_bytes || previous_hash)`
- **Version Hash**: `SHA256("WDB:VERSION:v1" || u32be(len(version_bytes)) || version_bytes || parent_version_hash)`
- **Merkle Leaf Hash**: `SHA256("WDB:LEAF:v1" || u32be(len(leaf_bytes)) || leaf_bytes)`
- **Merkle Internal Node Hash**: `SHA256("WDB:NODE:v1" || left_hash_32b || right_hash_32b)`
- **Empty Merkle Root**: `SHA256("WDB:EMPTY_ROOT:v1")`

## Policy Approval Signatures (v0.1 Frozen)

- **Algorithm**: Ed25519 (RFC 8032).
- **Signed Binary Payload**: `incident_id (16b) || protected_scope (UTF8) || target_version_id (16b) || proposed_changes_hash (32b) || requester_id (UTF8) || approver_pubkey (32b) || nonce (16b) || expires_at (8b I64)`
- **Validation**: Signature must verify against `approver_pubkey` registered in `authorization.trusted_approvers`. `approver_pubkey` MUST NOT match `requester_id` (Separation of Duties).

Normative definitions are in [`specs/WDB-0003-hash-chain.md`](file:///c:/Users/harsh/Documents/Codex/2026-08-13/referenced-chatgpt-conversation-this-is-an/wolverine-db/specs/WDB-0003-hash-chain.md), [`specs/WDB-0004-merkle-tree.md`](file:///c:/Users/harsh/Documents/Codex/2026-08-13/referenced-chatgpt-conversation-this-is-an/wolverine-db/specs/WDB-0004-merkle-tree.md), and [`specs/WDB-0006-recovery.md`](file:///c:/Users/harsh/Documents/Codex/2026-08-13/referenced-chatgpt-conversation-this-is-an/wolverine-db/specs/WDB-0006-recovery.md).
