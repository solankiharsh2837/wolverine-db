import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { ChangeRecordData, MutationOperation } from './types.js';

export function validateChangeRecordData(data: ChangeRecordData): void {
  if (data.formatVersion !== 1) {
    throw new WolverineError(
      WolverineErrorCode.UNKNOWN_RECORD_TYPE,
      `Unsupported format version: ${data.formatVersion}`
    );
  }
  if (!data.tableId || !data.tableId.includes('.')) {
    throw new WolverineError(
      WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
      `Invalid table identifier "${data.tableId}" (must be "schema.table")`
    );
  }
  if (!data.recordId || data.recordId.length === 0) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_PRIMARY_KEY_TUPLE,
      'Primary key tuple recordId payload cannot be empty'
    );
  }
  if (![MutationOperation.INSERT, MutationOperation.UPDATE, MutationOperation.DELETE].includes(data.operation)) {
    throw new WolverineError(
      WolverineErrorCode.UNKNOWN_RECORD_TYPE,
      `Invalid mutation operation: ${data.operation}`
    );
  }
  if (data.previousHash.length !== 32) {
    throw new WolverineError(
      WolverineErrorCode.MISSING_PREDECEASED_HASH,
      `Previous change hash must be 32 bytes, got ${data.previousHash.length}`
    );
  }
}
