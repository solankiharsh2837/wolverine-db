import { WolverineError, WolverineErrorCode } from '../errors/index.js';

const IDENTIFIER_REGEX = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/**
 * Validates that an identifier contains only safe SQL identifier characters.
 */
export function validateSqlIdentifier(identifier: string, paramName: string = 'identifier'): string {
  if (!identifier || !IDENTIFIER_REGEX.test(identifier)) {
    throw new WolverineError(
      WolverineErrorCode.TRIGGER_INSTALLATION_ERROR,
      `Invalid SQL identifier provided for ${paramName}: "${identifier}". Must match pattern ^[a-zA-Z_][a-zA-Z0-9_]*$`
    );
  }
  return identifier;
}

/**
 * Helper to generate PL/pgSQL trigger functions for protected tables with injection-safe quoting and mutation persistence.
 */
export function generateTableTriggerSql(
  schemaName: string,
  tableName: string,
  _primaryKeyCols: string[]
): string {
  const safeSchema = validateSqlIdentifier(schemaName, 'schemaName');
  const safeTable = validateSqlIdentifier(tableName, 'tableName');

  const quotedFullTable = `"${safeSchema}"."${safeTable}"`;
  const safeTriggerFuncName = `wolverine_sys_trg_${safeSchema}_${safeTable}`;
  const quotedTriggerFunc = `wolverine_sys."${safeTriggerFuncName}"`;

  // Build PL/pgSQL trigger function with change-capture persistence
  return `
CREATE OR REPLACE FUNCTION ${quotedTriggerFunc}()
RETURNS TRIGGER AS $$
DECLARE
  v_op INT;
  v_old_data JSONB := NULL;
  v_new_data JSONB := NULL;
  v_timestamp_us BIGINT;
BEGIN
  IF (TG_OP = 'INSERT') THEN
    v_op := 1;
    v_new_data := to_jsonb(NEW);
  ELSIF (TG_OP = 'UPDATE') THEN
    v_op := 2;
    v_old_data := to_jsonb(OLD);
    v_new_data := to_jsonb(NEW);
  ELSIF (TG_OP = 'DELETE') THEN
    v_op := 3;
    v_old_data := to_jsonb(OLD);
  END IF;

  v_timestamp_us := (extract(epoch from clock_timestamp()) * 1000000)::bigint;

  -- 1. Insert mutation into pending mutations buffer
  INSERT INTO wolverine_sys.pending_mutations (
    scope,
    op_type,
    old_data,
    new_data,
    created_at_us
  ) VALUES (
    TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME,
    v_op,
    v_old_data,
    v_new_data,
    v_timestamp_us
  );

  -- 2. Emit logical decoding message for streaming CDC receivers
  PERFORM pg_logical_emit_message(
    true,
    'wolverine_cdc',
    json_build_object(
      'scope', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME,
      'op', v_op,
      'old', v_old_data,
      'new', v_new_data,
      'ts', v_timestamp_us
    )::text
  );

  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_wolverine_capture ON ${quotedFullTable};
CREATE TRIGGER trg_wolverine_capture
AFTER INSERT OR UPDATE OR DELETE ON ${quotedFullTable}
FOR EACH ROW EXECUTE FUNCTION ${quotedTriggerFunc}();
`;
}
