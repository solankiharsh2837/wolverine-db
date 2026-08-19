import crypto from 'node:crypto';
import { BootstrapSnapshot, StateFrontierRow, StateFrontierSnapshot } from './types.js';
import { ChangeRecordData, MutationOperation } from '../protocol/types.js';
import { encodePrimaryKeyTuple } from '../binary/record_id.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { compareCanonicalStrings } from '../crypto/canonical.js';
import { MerkleTree } from '../crypto/merkle.js';
import { AnchoredCheckpoint } from '../checkpoint/types.js';
import { computeCheckpointDigest } from '../checkpoint/anchor.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export class DeterministicStateFrontier {
  private tables = new Map<string, Map<string, StateFrontierRow>>();
  private currentCommitSeq: bigint = 0n;
  private currentLsn: string = '0/0';
  private currentSchemaEpoch: number = 1;
  private currentChainHead: Buffer = Buffer.alloc(32, 0);
  private lastCheckpointId: string = '00000000-0000-0000-0000-000000000000';

  constructor(initialSchemaEpoch: number = 1) {
    this.currentSchemaEpoch = initialSchemaEpoch;
  }

  public get commitSeq(): bigint {
    return this.currentCommitSeq;
  }

  public get lsn(): string {
    return this.currentLsn;
  }

  public get schemaEpoch(): number {
    return this.currentSchemaEpoch;
  }

  public get chainHead(): Buffer {
    return Buffer.from(this.currentChainHead);
  }

  /**
   * Bootstraps the state frontier from an initial database snapshot (S_0).
   */
  public bootstrap(snapshot: BootstrapSnapshot): StateFrontierSnapshot {
    this.tables.clear();
    this.currentCommitSeq = 0n;
    this.currentLsn = snapshot.snapshotLsn;
    this.currentSchemaEpoch = snapshot.schemaEpoch;
    this.lastCheckpointId = snapshot.snapshotId;

    for (const row of snapshot.rows) {
      if (!this.tables.has(row.tableName)) {
        this.tables.set(row.tableName, new Map());
      }
      const tableMap = this.tables.get(row.tableName)!;
      const pkTuple = encodePrimaryKeyTuple(row.primaryKeyFields);
      const pkHex = pkTuple.toString('hex');

      tableMap.set(pkHex, {
        tableName: row.tableName,
        primaryKeyTuple: pkTuple,
        values: { ...row.values },
        versionId: snapshot.snapshotId,
        commitSeq: 0n,
        lsn: snapshot.snapshotLsn,
        deleted: false,
      });
    }

    const stateMerkleRoot = this.computeStateMerkleRoot();
    return {
      commitSeq: this.currentCommitSeq,
      lsn: this.currentLsn,
      schemaEpoch: this.currentSchemaEpoch,
      activeRowCount: this.getActiveRowCount(),
      stateMerkleRoot,
      changeChainHead: this.currentChainHead,
      timestampUs: snapshot.createdAtUs,
    };
  }

  /**
   * Applies a batch of committed transaction change records to the live state frontier.
   */
  public applyChangeRecords(
    changes: ChangeRecordData[],
    commitLsn: string,
    commitSeq: bigint,
    changeHead: Buffer
  ): StateFrontierSnapshot {
    if (commitSeq <= this.currentCommitSeq && this.currentCommitSeq > 0n) {
      throw new WolverineError(
        WolverineErrorCode.SEQUENCE_GAP_DETECTED,
        `Monotonic commit sequence violation: expected > ${this.currentCommitSeq}, received ${commitSeq}`
      );
    }

    for (const change of changes) {
      const tableName = change.tableId;
      if (!this.tables.has(tableName)) {
        this.tables.set(tableName, new Map());
      }
      const tableMap = this.tables.get(tableName)!;
      const pkHex = change.recordId.toString('hex');

      if (change.operation === MutationOperation.INSERT) {
        const newValues = (change.fieldSet.new as Record<string, unknown>) || {};
        tableMap.set(pkHex, {
          tableName,
          primaryKeyTuple: change.recordId,
          values: { ...newValues },
          versionId: change.versionId,
          commitSeq,
          lsn: commitLsn,
          deleted: false,
        });
      } else if (change.operation === MutationOperation.UPDATE) {
        const existing = tableMap.get(pkHex);
        const existingValues = existing && !existing.deleted ? existing.values : {};
        const updateValues = (change.fieldSet.new as Record<string, unknown>) || {};
        const mergedValues = { ...existingValues, ...updateValues };

        tableMap.set(pkHex, {
          tableName,
          primaryKeyTuple: change.recordId,
          values: mergedValues,
          versionId: change.versionId,
          commitSeq,
          lsn: commitLsn,
          deleted: false,
        });
      } else if (change.operation === MutationOperation.DELETE) {
        tableMap.delete(pkHex);
      }
    }

    this.currentCommitSeq = commitSeq;
    this.currentLsn = commitLsn;
    this.currentChainHead = Buffer.from(changeHead);

    const stateMerkleRoot = this.computeStateMerkleRoot();
    const lastTimestampUs = changes.length > 0 ? changes[changes.length - 1]!.timestampUs : BigInt(Date.now()) * 1000n;

    return {
      commitSeq: this.currentCommitSeq,
      lsn: this.currentLsn,
      schemaEpoch: this.currentSchemaEpoch,
      activeRowCount: this.getActiveRowCount(),
      stateMerkleRoot,
      changeChainHead: this.currentChainHead,
      timestampUs: lastTimestampUs,
    };
  }

  /**
   * Advances schema epoch upon DDL migrations or epoch rotations.
   */
  public incrementSchemaEpoch(): number {
    this.currentSchemaEpoch++;
    return this.currentSchemaEpoch;
  }

  public setSchemaEpoch(epoch: number): void {
    this.currentSchemaEpoch = epoch;
  }

  /**
   * Computes deterministic RFC 6962 Merkle tree state root over sorted canonical row representations.
   */
  public computeStateMerkleRoot(): Buffer {
    const rowHashes: { sortKey: string; hash: Buffer }[] = [];

    for (const [tableName, tableMap] of this.tables.entries()) {
      for (const [pkHex, row] of tableMap.entries()) {
        if (row.deleted) continue;

        const canonicalRowJson = canonicalizeJson({
          table: tableName,
          pk: pkHex,
          values: row.values,
          epoch: this.currentSchemaEpoch,
        });

        const rowHash = crypto
          .createHash('sha256')
          .update(Buffer.from(canonicalRowJson, 'utf8'))
          .digest();

        rowHashes.push({
          sortKey: `${tableName}:${pkHex}`,
          hash: rowHash,
        });
      }
    }

    if (rowHashes.length === 0) {
      return Buffer.alloc(32, 0);
    }

    // Sort deterministically using UTF-8 byte comparison (locale-independent)
    rowHashes.sort((a, b) => compareCanonicalStrings(a.sortKey, b.sortKey));

    const leaves = rowHashes.map((r) => r.hash);
    const tree = new MerkleTree(leaves);
    return tree.root;
  }

  /**
   * Generates a verifiable AnchoredCheckpoint for the current state frontier.
   */
  public createCheckpoint(
    checkpointId: string,
    scope: string = 'global',
    protocolVersion: number = 3
  ): AnchoredCheckpoint {
    const merkleRoot = this.computeStateMerkleRoot();
    const createdAtUs = BigInt(Date.now()) * 1000n;

    const partialCheckpoint = {
      checkpointId,
      scope,
      commitSeq: this.currentCommitSeq,
      previousCheckpointId: this.lastCheckpointId,
      merkleRoot,
      changeChainHead: this.currentChainHead,
      createdAtUs,
      protocolVersion,
    };

    const digest = computeCheckpointDigest(partialCheckpoint);
    this.lastCheckpointId = checkpointId;

    return {
      ...partialCheckpoint,
      digest,
    };
  }

  public getActiveRowCount(): number {
    let count = 0;
    for (const tableMap of this.tables.values()) {
      for (const row of tableMap.values()) {
        if (!row.deleted) count++;
      }
    }
    return count;
  }

  public getLiveRow(tableName: string, pkHex: string): StateFrontierRow | undefined {
    return this.tables.get(tableName)?.get(pkHex);
  }
}
