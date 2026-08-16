import { ChangeRecordData, MutationOperation } from '../protocol/types.js';
import { validateChangeRecordData } from '../protocol/validators.js';
import { WalTransactionBlock } from './types.js';
import { encodePrimaryKeyTuple } from '../binary/record_id.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { encodeBinaryRecord, TaggedField } from '../binary/encoder.js';
import { computeChangeHash } from '../crypto/hash.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface NormalizedWalChange {
  changeRecordData: ChangeRecordData;
  recordBytes: Buffer;
  changeHash: Buffer;
}

export class WalNormalizer {
  /**
   * Normalizes a raw WAL transaction block into an array of canonical ChangeRecordData
   * and computes deterministic binary records and hashes.
   */
  public normalizeTransaction(
    block: WalTransactionBlock,
    versionId: string,
    previousHash: Buffer,
    protectedTables?: string[]
  ): NormalizedWalChange[] {
    const results: NormalizedWalChange[] = [];
    let currentPrevHash = Buffer.from(previousHash);

    for (const mutation of block.mutations) {
      if (!mutation.schema || !mutation.table) {
        throw new WolverineError(
          WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
          `Invalid table identifier "${mutation.schema}.${mutation.table}" (must be "schema.table")`
        );
      }
      const tableId = `${mutation.schema}.${mutation.table}`;

      // If protected tables filter is active and this table is not included, skip
      if (protectedTables && protectedTables.length > 0 && !protectedTables.includes(tableId)) {
        continue;
      }

      const operation =
        mutation.action === 'I'
          ? MutationOperation.INSERT
          : mutation.action === 'U'
          ? MutationOperation.UPDATE
          : MutationOperation.DELETE;

      // Encode canonical binary primary key tuple (WDB-0002)
      const recordId = encodePrimaryKeyTuple(mutation.primaryKeyFields);

      // Build canonical fieldSet normalized via RFC 8785
      const fieldSetObj = {
        new: mutation.newValues,
        old: mutation.oldValues,
      };

      const provenanceObj = {
        origin: 'wal_replication',
        xid: block.xid,
        commitLsn: block.commitLsn,
      };

      const changeRecordData: ChangeRecordData = {
        formatVersion: 1,
        versionId,
        transactionId: `tx:${block.xid}`,
        timestampUs: block.commitTimestampUs,
        tableId,
        recordId,
        operation,
        fieldSet: fieldSetObj,
        provenance: provenanceObj,
        previousHash: currentPrevHash,
      };

      // Construct canonical binary tagged fields according to WDB-0001 & WDB-0002
      const formatVerBuf = Buffer.alloc(8);
      formatVerBuf.writeBigUInt64BE(1n, 0);

      const versionIdBuf = Buffer.alloc(16);
      Buffer.from(versionId.replace(/-/g, ''), 'hex').copy(versionIdBuf, 0);

      const txIdBuf = Buffer.from(changeRecordData.transactionId, 'utf8');

      const timestampBuf = Buffer.alloc(8);
      timestampBuf.writeBigInt64BE(changeRecordData.timestampUs, 0);

      const tableIdBuf = Buffer.from(changeRecordData.tableId, 'utf8');

      const opBuf = Buffer.alloc(8);
      opBuf.writeBigUInt64BE(BigInt(operation), 0);

      const fieldSetJsonStr = canonicalizeJson(fieldSetObj);
      const fieldSetBuf = Buffer.from(fieldSetJsonStr, 'utf8');

      const provenanceJsonStr = canonicalizeJson(provenanceObj);
      const provenanceBuf = Buffer.from(provenanceJsonStr, 'utf8');

      const fields: TaggedField[] = [
        { tag: 1, typeTag: 2, payload: formatVerBuf },
        { tag: 2, typeTag: 4, payload: versionIdBuf },
        { tag: 3, typeTag: 5, payload: txIdBuf },
        { tag: 4, typeTag: 10, payload: timestampBuf },
        { tag: 5, typeTag: 5, payload: tableIdBuf },
        { tag: 6, typeTag: 6, payload: recordId },
        { tag: 7, typeTag: 2, payload: opBuf },
        { tag: 8, typeTag: 8, payload: fieldSetBuf },
        { tag: 9, typeTag: 8, payload: provenanceBuf },
        { tag: 10, typeTag: 7, payload: currentPrevHash },
      ];

      // Enforce structural & semantic validation
      validateChangeRecordData(changeRecordData);

      const recordBytes = encodeBinaryRecord(1, fields);
      const changeHash = computeChangeHash(recordBytes, currentPrevHash);

      results.push({
        changeRecordData,
        recordBytes,
        changeHash,
      });

      // Chain advance
      currentPrevHash = Buffer.from(changeHash);
    }

    return results;
  }
}
