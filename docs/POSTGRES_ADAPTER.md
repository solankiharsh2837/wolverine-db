# WolverineDB // PostgreSQL Adapter & Replication Specification

> **Source Code is Authoritative.**  
> This document specifies the PostgreSQL logical decoding integration, schema migrations, durable nonce store, and WAL normalization pipeline of **WolverineDB v1.3.0**.

---

## 1. Overview & Connection Architecture

The WolverineDB PostgreSQL Adapter ([`src/postgres/adapter.ts`](../src/postgres/adapter.ts)) interfaces with PostgreSQL instances via `pg` connection pools. It provides two operational modes:
1. **Logical Replication Consumer**: Subscribes to PostgreSQL `pgoutput` or `test_decoding` replication slots to stream transaction mutations.
2. **Synchronous Trust Anchor**: Queries and records durable recovery approval nonces and validates table state roots against on-chain anchors.

---

## 2. PostgreSQL System Schema (`wolverine_sys`)

The adapter manages an internal system schema `wolverine_sys` defined in [`src/postgres/schema.ts`](../src/postgres/schema.ts):

```sql
CREATE SCHEMA IF NOT EXISTS wolverine_sys;

-- Durable approval nonce tracking (Issue #1 fix)
CREATE TABLE IF NOT EXISTS wolverine_sys.approval_nonces (
    nonce_uuid UUID PRIMARY KEY,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id TEXT,
    database_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_wolverine_approval_nonces_tenant 
ON wolverine_sys.approval_nonces(tenant_id, database_id);
```

---

## 3. Durable Nonce Store (`PostgresNonceStore`)

To prevent replay attacks during disaster recovery, WolverineDB implements [`PostgresNonceStore`](../src/postgres/nonce_store.ts#L5) satisfying the [`IApprovalNonceStore`](../src/engine/nonce_store.ts#L10) interface.

### Atomic Insertion & Collision Detection:
```ts
public async recordConsumedNonce(
  nonce: Buffer | string,
  metadata?: { tenantId?: string; databaseId?: string }
): Promise<boolean> {
  const nonceUuid = formatNonceUuid(nonce);
  try {
    await this.adapter.query(
      `INSERT INTO wolverine_sys.approval_nonces (nonce_uuid, consumed_at, tenant_id, database_id)
       VALUES ($1, NOW(), $2, $3)`,
      [nonceUuid, metadata?.tenantId ?? null, metadata?.databaseId ?? null]
    );
    return true;
  } catch (err: any) {
    // PostgreSQL error 23505: unique_violation
    if (err.code === '23505') {
      return false;
    }
    throw err;
  }
}
```

---

## 4. WAL Normalization Pipeline

Raw PostgreSQL WAL messages contain database-specific physical representations (OID references, raw binary tuples, transaction LSNs).

The normalization flow in [`src/wal/normalizer.ts`](../src/wal/normalizer.ts):
```
Raw PostgreSQL WAL Message
           ↓
WalDecoder (src/wal/decoder.ts)
  - Extracts table name, schema, action (INSERT/UPDATE/DELETE)
  - Decodes tuple old/new column value dictionaries
           ↓
WalNormalizer (src/wal/normalizer.ts)
  - Normalizes timestamps to UTC microseconds (createdAtUs)
  - Formats numeric/decimal types as exact strings
  - Serializes primary key components into canonical primaryKeyHex
           ↓
Canonical MutationTuple (ready for Merkle leaf hashing)
```
