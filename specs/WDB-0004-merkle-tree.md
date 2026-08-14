# WDB-0004: Merkle tree

Status: Normative Specification (v0.1 Frozen).

## Leaf Key Encoding & Sorting

- Checkpoint leaves are sorted lexicographically by their canonical leaf key tuple:
  `leaf_key = protected_scope (UTF8) || canonical_record_key (BYTES) || version_id (UUID)`
- `canonical_record_key` is the Canonical Primary Key Tuple binary encoding defined in WDB-0002.

## Hash Formulas

- **Leaf Hash**: `leaf = SHA256("WDB:LEAF:v1" || u32be(len(leaf_bytes)) || leaf_bytes)`
- **Internal Node Hash**: `node = SHA256("WDB:NODE:v1" || left_hash_32b || right_hash_32b)`

## Tree Construction & Odd Counts

- Level construction pairs adjacent nodes from left to right.
- If a level contains an odd number of nodes, the final node hash is duplicated to form a pair.
- Tree reduction continues level-by-level until a single 32-byte root hash remains.

## Empty Tree Root Constant

- If a protected scope contains zero records, the Merkle tree root is the fixed constant:
  `EMPTY_ROOT = SHA256("WDB:EMPTY_ROOT:v1")` (Hex: `e7c858...` - exact vector specified in `TEST-VECTORS.md`).

## Inclusion Proofs & Verification

- An inclusion proof is an ordered array of `{ side: 0 | 1, sibling_hash: 32_bytes }` (where `0` = sibling on left, `1` = sibling on right).
- Verification recalculates the root from the leaf hash and proof steps, succeeding if and only if the calculated root equals the checkpoint root using a constant-time 32-byte equality comparison.
