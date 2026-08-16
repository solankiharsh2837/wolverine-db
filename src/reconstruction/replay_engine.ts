import crypto from 'node:crypto';
import { ChangeRecordData, MutationOperation } from '../protocol/types.js';
import { TableRowVersion, ReconstructedDatabaseState } from './types.js';
import { MerkleTree } from '../crypto/merkle.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { compareCanonicalStrings } from '../crypto/canonical.js';

export class StateReplayEngine {
  /**
   * Replays a contiguous list of authorized changes into a materialized database state.
   */
  public static replayChanges(
    initialState: ReconstructedDatabaseState,
    changes: ChangeRecordData[]
  ): ReconstructedDatabaseState {
    const state: ReconstructedDatabaseState = new Map();

    // Deep clone initial state
    for (const [table, rows] of initialState.entries()) {
      const tableRows = new Map<string, TableRowVersion>();
      for (const [pkHex, row] of rows.entries()) {
        tableRows.set(pkHex, { ...row, values: { ...row.values } });
      }
      state.set(table, tableRows);
    }

    for (const change of changes) {
      const tableName = change.tableId;
      if (!state.has(tableName)) {
        state.set(tableName, new Map());
      }
      const tableRows = state.get(tableName)!;
      const pkHex = change.recordId.toString('hex');

      if (change.operation === MutationOperation.INSERT) {
        const newValues = (change.fieldSet.new as Record<string, unknown>) || {};
        tableRows.set(pkHex, {
          tableName,
          primaryKeyTuple: change.recordId,
          values: newValues,
          versionId: change.versionId,
          commitSeq: change.timestampUs,
          deleted: false,
        });
      } else if (change.operation === MutationOperation.UPDATE) {
        const existing = tableRows.get(pkHex);
        const existingValues = existing ? existing.values : {};
        const updateValues = (change.fieldSet.new as Record<string, unknown>) || {};
        const mergedValues = { ...existingValues, ...updateValues };

        tableRows.set(pkHex, {
          tableName,
          primaryKeyTuple: change.recordId,
          values: mergedValues,
          versionId: change.versionId,
          commitSeq: change.timestampUs,
          deleted: false,
        });
      } else if (change.operation === MutationOperation.DELETE) {
        tableRows.delete(pkHex);
      }
    }

    return state;
  }

  /**
   * Computes the deterministic Merkle root over all live rows across all tables.
   */
  public static computeStateMerkleRoot(state: ReconstructedDatabaseState): Buffer {
    const rowHashes: { pkSortKey: string; hash: Buffer }[] = [];

    for (const [tableName, rows] of state.entries()) {
      for (const [pkHex, row] of rows.entries()) {
        if (row.deleted) continue;

        const canonicalRowJson = canonicalizeJson({
          table: tableName,
          pk: pkHex,
          values: row.values,
        });

        const rowHash = crypto
          .createHash('sha256')
          .update(Buffer.from(canonicalRowJson, 'utf8'))
          .digest();

        rowHashes.push({
          pkSortKey: `${tableName}:${pkHex}`,
          hash: rowHash,
        });
      }
    }

    if (rowHashes.length === 0) {
      return Buffer.alloc(32, 0);
    }

    // Sort deterministically by table and primary key (locale-independent)
    rowHashes.sort((a, b) => compareCanonicalStrings(a.pkSortKey, b.pkSortKey));

    const leaves = rowHashes.map((r) => r.hash);
    const tree = new MerkleTree(leaves);
    return tree.root;
  }
}
