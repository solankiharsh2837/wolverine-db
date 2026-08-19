import { PgOutputMessage, PgOutputColumn } from '../evidence/types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { PrimaryKeyField } from '../binary/record_id.js';

export interface PgRelationMetadata {
  relationId: number;
  schema: string;
  table: string;
  replicaIdentity: string;
  columns: PgOutputColumn[];
}

export class PgOutputDecoder {
  private relations = new Map<number, PgRelationMetadata>();

  public getRelation(relationId: number): PgRelationMetadata | undefined {
    return this.relations.get(relationId);
  }

  public registerRelation(metadata: PgRelationMetadata): void {
    this.relations.set(metadata.relationId, metadata);
  }

  /**
   * Decodes a binary pgoutput message buffer.
   */
  public decodeMessage(buffer: Buffer): PgOutputMessage {
    if (buffer.length === 0) {
      throw new WolverineError(WolverineErrorCode.MALFORMED_FIELD_PAYLOAD, 'Empty pgoutput buffer');
    }

    let offset = 0;
    const msgType = String.fromCharCode(buffer[offset++]!);

    switch (msgType) {
      case 'B': {
        // Begin
        const commitLsnBig = buffer.readBigUInt64BE(offset);
        offset += 8;
        const commitTimeUs = buffer.readBigInt64BE(offset);
        offset += 8;
        const xid = buffer.readUInt32BE(offset);
        offset += 4;

        return {
          type: 'B',
          xid: String(xid),
          commitLsn: this.formatLsn(commitLsnBig),
          commitTimeUs,
        };
      }

      case 'C': {
        // Commit
        const flags = buffer[offset++]!;
        const commitLsnBig = buffer.readBigUInt64BE(offset);
        offset += 8;
        const endLsnBig = buffer.readBigUInt64BE(offset);
        offset += 8;
        const commitTimeUs = buffer.readBigInt64BE(offset);
        offset += 8;

        return {
          type: 'C',
          flags,
          commitLsn: this.formatLsn(commitLsnBig),
          endLsn: this.formatLsn(endLsnBig),
          commitTimeUs,
        };
      }

      case 'R': {
        // Relation
        const relationId = buffer.readUInt32BE(offset);
        offset += 4;

        const { str: schema, nextOffset: off1 } = this.readNullTerminatedString(buffer, offset);
        offset = off1;

        const { str: table, nextOffset: off2 } = this.readNullTerminatedString(buffer, offset);
        offset = off2;

        const replicaIdentity = String.fromCharCode(buffer[offset++]!);
        const numColumns = buffer.readUInt16BE(offset);
        offset += 2;

        const columns: PgOutputColumn[] = [];
        for (let i = 0; i < numColumns; i++) {
          const flags = buffer[offset++]!;
          const { str: colName, nextOffset: offCol } = this.readNullTerminatedString(buffer, offset);
          offset = offCol;

          const typeOid = buffer.readUInt32BE(offset);
          offset += 4;
          const typeModifier = buffer.readInt32BE(offset);
          offset += 4;

          columns.push({
            flags,
            name: colName,
            typeOid,
            typeModifier,
          });
        }

        const relationMetadata: PgRelationMetadata = {
          relationId,
          schema,
          table,
          replicaIdentity,
          columns,
        };
        this.relations.set(relationId, relationMetadata);

        return {
          type: 'R',
          relationId,
          schema,
          table,
          replicaIdentity,
          columns,
        };
      }

      case 'I': {
        // Insert
        const relationId = buffer.readUInt32BE(offset);
        offset += 4;

        const tupleType = String.fromCharCode(buffer[offset++]!);
        if (tupleType !== 'N') {
          throw new WolverineError(
            WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
            `Expected 'N' for Insert tuple, observed '${tupleType}'`
          );
        }

        const relation = this.relations.get(relationId);
        const { tupleData } = this.readTupleData(buffer, offset, relation);

        return {
          type: 'I',
          relationId,
          tupleData,
        };
      }

      case 'U': {
        // Update
        const relationId = buffer.readUInt32BE(offset);
        offset += 4;

        const relation = this.relations.get(relationId);
        let subType = String.fromCharCode(buffer[offset++]!);

        let keyTupleData: Record<string, unknown> | undefined;
        let oldTupleData: Record<string, unknown> | undefined;

        if (subType === 'K') {
          const res = this.readTupleData(buffer, offset, relation);
          keyTupleData = res.tupleData;
          offset = res.nextOffset;
          subType = String.fromCharCode(buffer[offset++]!);
        } else if (subType === 'O') {
          const res = this.readTupleData(buffer, offset, relation);
          oldTupleData = res.tupleData;
          offset = res.nextOffset;
          subType = String.fromCharCode(buffer[offset++]!);
        }

        if (subType !== 'N') {
          throw new WolverineError(
            WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
            `Expected 'N' for new Update tuple, observed '${subType}'`
          );
        }

        const { tupleData } = this.readTupleData(buffer, offset, relation);

        return {
          type: 'U',
          relationId,
          keyTupleData,
          oldTupleData,
          tupleData,
        };
      }

      case 'D': {
        // Delete
        const relationId = buffer.readUInt32BE(offset);
        offset += 4;

        const relation = this.relations.get(relationId);
        const subType = String.fromCharCode(buffer[offset++]!);

        let keyTupleData: Record<string, unknown> | undefined;
        let oldTupleData: Record<string, unknown> | undefined;

        if (subType === 'K') {
          const res = this.readTupleData(buffer, offset, relation);
          keyTupleData = res.tupleData;
        } else if (subType === 'O') {
          const res = this.readTupleData(buffer, offset, relation);
          oldTupleData = res.tupleData;
        }

        return {
          type: 'D',
          relationId,
          keyTupleData,
          oldTupleData,
        };
      }

      case 'T': {
        // Truncate
        const numRelations = buffer.readUInt32BE(offset);
        offset += 4;
        const options = buffer[offset++]!;
        const relationIds: number[] = [];

        for (let i = 0; i < numRelations; i++) {
          relationIds.push(buffer.readUInt32BE(offset));
          offset += 4;
        }

        return {
          type: 'T',
          options,
          relationIds,
        };
      }

      default:
        throw new WolverineError(
          WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
          `Unknown pgoutput message type '${msgType}'`
        );
    }
  }

  public extractPrimaryKeyFields(
    relation: PgRelationMetadata,
    tupleData: Record<string, unknown>
  ): PrimaryKeyField[] {
    const pkFields: PrimaryKeyField[] = [];

    for (const col of relation.columns) {
      if ((col.flags & 1) === 1 || col.name === 'id' || col.name.endsWith('_id') || col.name === 'pk') {
        const val = tupleData[col.name];
        if (val !== undefined && val !== null) {
          pkFields.push({
            name: col.name,
            typeTag: col.typeOid === 2950 ? 4 : 5, // UUID or UTF8 String
            valueBuffer: Buffer.from(String(val), 'utf8'),
          });
        }
      }
    }

    if (pkFields.length === 0 && Object.keys(tupleData).length > 0) {
      const firstCol = Object.keys(tupleData)[0]!;
      pkFields.push({
        name: firstCol,
        typeTag: 5,
        valueBuffer: Buffer.from(String(tupleData[firstCol]), 'utf8'),
      });
    }

    return pkFields;
  }

  private readTupleData(
    buffer: Buffer,
    startOffset: number,
    relation?: PgRelationMetadata
  ): { tupleData: Record<string, unknown>; nextOffset: number } {
    let offset = startOffset;
    const numColumns = buffer.readUInt16BE(offset);
    offset += 2;

    const tupleData: Record<string, unknown> = {};

    for (let colIdx = 0; colIdx < numColumns; colIdx++) {
      const colName = relation?.columns[colIdx]?.name || `col_${colIdx}`;
      const colKind = String.fromCharCode(buffer[offset++]!);

      if (colKind === 'n') {
        // NULL
        tupleData[colName] = null;
      } else if (colKind === 'u') {
        // Unchanged TOASTed value
        tupleData[colName] = undefined;
      } else if (colKind === 't' || colKind === 'b') {
        // Text or Binary data
        const len = buffer.readUInt32BE(offset);
        offset += 4;
        const textVal = buffer.subarray(offset, offset + len).toString('utf8');
        offset += len;
        tupleData[colName] = textVal;
      }
    }

    return { tupleData, nextOffset: offset };
  }

  private readNullTerminatedString(buffer: Buffer, startOffset: number): { str: string; nextOffset: number } {
    let nullIndex = startOffset;
    while (nullIndex < buffer.length && buffer[nullIndex] !== 0) {
      nullIndex++;
    }
    const str = buffer.subarray(startOffset, nullIndex).toString('utf8');
    return { str, nextOffset: nullIndex + 1 };
  }

  private formatLsn(lsnBig: bigint): string {
    const high = Number(lsnBig >> 32n).toString(16).toUpperCase();
    const low = Number(lsnBig & 0xffffffffn).toString(16).toUpperCase();
    return `${high}/${low}`;
  }
}
