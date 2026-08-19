/**
 * DDL and SQL definitions for wolverine_sys metadata schema
 */
export const CREATE_WOLVERINE_SYS_SCHEMA_SQL = `
CREATE SCHEMA IF NOT EXISTS wolverine_sys;

-- Sequence generator for monotonic transaction commit sequence
CREATE SEQUENCE IF NOT EXISTS wolverine_sys.commit_seq START WITH 1 INCREMENT BY 1;

-- Table storing append-only committed change history records
CREATE TABLE IF NOT EXISTS wolverine_sys.change_history (
  change_seq BIGINT PRIMARY KEY DEFAULT nextval('wolverine_sys.commit_seq'),
  change_hash BYTEA NOT NULL,
  previous_hash BYTEA NOT NULL,
  version_id UUID NOT NULL,
  transaction_id TEXT NOT NULL,
  timestamp_us BIGINT NOT NULL,
  table_id TEXT NOT NULL,
  record_id BYTEA NOT NULL,
  operation INT NOT NULL,
  record_bytes BYTEA NOT NULL,
  created_at TIMESTAMPTZ DEFAULT clock_timestamp()
);

-- Index for change hash lookup and sequence traversal
CREATE INDEX IF NOT EXISTS idx_change_history_seq ON wolverine_sys.change_history (change_seq);
CREATE INDEX IF NOT EXISTS idx_change_history_hash ON wolverine_sys.change_history (change_hash);

-- Table storing append-only immutable database state versions
CREATE TABLE IF NOT EXISTS wolverine_sys.versions (
  version_id UUID PRIMARY KEY,
  parent_version_id UUID NOT NULL,
  version_hash BYTEA NOT NULL,
  transaction_id TEXT NOT NULL,
  commit_timestamp_us BIGINT NOT NULL,
  state_root BYTEA NOT NULL,
  status INT NOT NULL, -- 1=ACTIVE, 2=SUPERSEDED, 3=RECOVERED
  created_at TIMESTAMPTZ DEFAULT clock_timestamp()
);

-- Table storing Merkle state checkpoints
CREATE TABLE IF NOT EXISTS wolverine_sys.checkpoints (
  checkpoint_id UUID PRIMARY KEY,
  protected_scope TEXT NOT NULL,
  version_id UUID NOT NULL REFERENCES wolverine_sys.versions(version_id),
  leaf_count INT NOT NULL,
  merkle_root BYTEA NOT NULL,
  timestamp_us BIGINT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT clock_timestamp()
);

-- Table storing consumed approval nonces for replay prevention
CREATE TABLE IF NOT EXISTS wolverine_sys.approval_nonces (
  nonce UUID PRIMARY KEY,
  incident_id UUID NOT NULL,
  approver_pubkey BYTEA NOT NULL,
  consumed_at TIMESTAMPTZ DEFAULT clock_timestamp()
);

-- Table storing detected integrity incidents
CREATE TABLE IF NOT EXISTS wolverine_sys.incidents (
  incident_id UUID PRIMARY KEY,
  protected_scope TEXT NOT NULL,
  incident_type TEXT NOT NULL,
  detected_at_us BIGINT NOT NULL,
  details JSONB NOT NULL
);

-- Table storing non-destructive recovery proposals
CREATE TABLE IF NOT EXISTS wolverine_sys.recovery_proposals (
  proposal_id UUID PRIMARY KEY,
  incident_id UUID NOT NULL REFERENCES wolverine_sys.incidents(incident_id),
  protected_scope TEXT NOT NULL,
  target_version_id UUID NOT NULL,
  proposed_changes_hash BYTEA NOT NULL,
  requester_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING'
);

-- Legacy pending mutations buffer table for fallback compatibility
CREATE TABLE IF NOT EXISTS wolverine_sys.pending_mutations (
  mutation_id BIGSERIAL PRIMARY KEY,
  scope TEXT NOT NULL,
  table_name TEXT,
  record_id TEXT,
  op_type TEXT NOT NULL,
  old_data JSONB,
  new_data JSONB,
  created_at_us BIGINT NOT NULL
);
`;
