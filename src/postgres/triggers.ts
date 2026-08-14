/**
 * Helper to generate PL/pgSQL trigger functions for protected tables
 */
export function generateTableTriggerSql(schemaName: string, tableName: string, _primaryKeyCols: string[]): string {
  const fullTableName = `${schemaName}.${tableName}`;
  const triggerFuncName = `wolverine_sys_trg_${schemaName}_${tableName}`;

  // Build PL/pgSQL trigger function
  return `
CREATE OR REPLACE FUNCTION wolverine_sys.${triggerFuncName}()
RETURNS TRIGGER AS $$
DECLARE
  v_op INT;
  v_old_data JSONB := NULL;
  v_new_data JSONB := NULL;
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

  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_wolverine_capture ON ${fullTableName};
CREATE TRIGGER trg_wolverine_capture
AFTER INSERT OR UPDATE OR DELETE ON ${fullTableName}
FOR EACH ROW EXECUTE FUNCTION wolverine_sys.${triggerFuncName}();
`;
}
