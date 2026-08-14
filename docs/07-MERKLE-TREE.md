# Merkle tree

Checkpoint leaves are ordered lexicographically by the canonical byte tuple `(protected_scope, canonical_record_key, version_id)` where `canonical_record_key` is the binary primary key tuple encoding defined in WDB-0002.

- **Leaf Hash**: `SHA256("WDB:LEAF:v1" || u32be(len(leaf_bytes)) || leaf_bytes)`
- **Internal Node Hash**: `SHA256("WDB:NODE:v1" || left || right)`
- **Odd Node Handling**: Duplicate the final hash at that level before pairing.
- **Empty Tree Root**: For empty protected scopes with zero records, the root hash is the fixed constant `SHA256("WDB:EMPTY_ROOT:v1")`.

Inclusion proofs contain sibling hashes and side indicators (`left` / `right`) and are verified from leaf to root using constant-time hash comparisons. Normative spec: [`specs/WDB-0004-merkle-tree.md`](file:///c:/Users/harsh/Documents/Codex/2026-08-13/referenced-chatgpt-conversation-this-is-an/wolverine-db/specs/WDB-0004-merkle-tree.md).
