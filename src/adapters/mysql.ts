import { UniversalDatabaseAdapter, DatabaseMutationEvent } from './types.js';
import { ChangeRecordData } from '../protocol/types.js';
import { encodePrimaryKeyTuple } from '../binary/record_id.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { encodeBinaryRecord, TaggedField } from '../binary/encoder.js';
import { computeChangeHash } from '../crypto/hash.js';

export class MySqlAdapter implements UniversalDatabaseAdapter {
  public readonly engineName = 'mysql';

  public normalizeMutation(
    event: DatabaseMutationEvent,
    versionId: string,
    previousHash: Buffer
  ): {
    changeRecordData: ChangeRecordData;
    recordBytes: Buffer;
    changeHash: Buffer;
  } {
    const tableId = `${event.schema}.${event.table}`;
    const recordId = encodePrimaryKeyTuple(event.primaryKeyFields);

    const fieldSetObj = {
      new: event.newValues,
      old: event.oldValues,
    };

    const provenanceObj = {
      engine: 'mysql',
      gtid: event.txId,
    };

    const changeRecordData: ChangeRecordData = {
      formatVersion: 1,
      versionId,
      transactionId: `mysql-gtid:${event.txId}`,
      timestampUs: event.commitTimestampUs,
      tableId,
      recordId,
      operation: event.operation,
      fieldSet: fieldSetObj,
      provenance: provenanceObj,
      previousHash,
    };

    const formatVerBuf = Buffer.alloc(8);
    formatVerBuf.writeBigUInt64BE(1n, 0);

    const versionIdBuf = Buffer.alloc(16);
    Buffer.from(versionId.replace(/-/g, ''), 'hex').copy(versionIdBuf, 0);

    const txIdBuf = Buffer.from(changeRecordData.transactionId, 'utf8');

    const timestampBuf = Buffer.alloc(8);
    timestampBuf.writeBigInt64BE(changeRecordData.timestampUs, 0);

    const tableIdBuf = Buffer.from(changeRecordData.tableId, 'utf8');

    const opBuf = Buffer.alloc(8);
    opBuf.writeBigUInt64BE(BigInt(event.operation), 0);

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
      { tag: 10, typeTag: 7, payload: previousHash },
    ];

    const recordBytes = encodeBinaryRecord(1, fields);
    const changeHash = computeChangeHash(recordBytes, previousHash);

    return {
      changeRecordData,
      recordBytes,
      changeHash,
    };
  }
}
