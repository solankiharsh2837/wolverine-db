# WDB-0063: Authorized State Replay Engine Protocol

Status: Normative Specification (v0.6.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the deterministic replay of verified canonical change records from a verified base checkpoint up to the Recovery Boundary.

## 2. In-Memory State Model

The replay engine maintains an in-memory materialization of tables and rows:

```typescript
export interface TableRowVersion {
  primaryKeyTuple: Buffer;
  values: Record<string, unknown>;
  versionId: string;
  commitSeq: bigint;
  deleted: boolean;
}

export type ReconstructedDatabaseState = Map<string, Map<string, TableRowVersion>>;
```

## 3. Replay Transition Rules

For each authorized `ChangeRecordData` $R_i$:
1. **`INSERT` (Op 1)**: Adds new `TableRowVersion` with `newValues` at primary key tuple.
2. **`UPDATE` (Op 2)**: Overwrites values with `newValues`, preserving unmentioned fields from prior version.
3. **`DELETE` (Op 3)**: Sets `deleted: true` or removes key from active table state map.

## 4. Merkle Root Determinism

After replaying all authorized changes up to the Recovery Boundary, the state Merkle tree is reconstructed:
1. Every active non-deleted row version is converted to a canonical binary representation (`WDB-0002`).
2. Row hashes are sorted lexicographically by primary key buffer.
3. The Merkle tree is computed deterministically (`WDB-0004`).
4. The resulting root ($M_{\text{reconstructed}}$) is committed to the Reconstruction Manifest.
