# WDB-0025: Universal Multi-Database Adapters

Status: Normative Specification (v0.3 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the universal database capture interface across heterogeneous relational engines (PostgreSQL, MySQL, SQLite).

## 2. Invariant: Identical Cryptographic Semantics

Database adapters **MUST NOT** redefine or customize WolverineDB cryptographic primitives. Regardless of database engine origin, all capture feeds MUST converge upon the exact same canonical pipeline:

```
Database Mutation (PG WAL / MySQL Binlog / SQLite Hook)
               │
               ▼
        Capture Normalizer
               │
               ▼
     Canonical ChangeRecordData (WDB-0001)
               │
               ▼
     Canonical Binary Format (WDB-0002)
               │
               ▼
         SHA-256 Hash Chain (WDB-0003)
               │
               ▼
        Merkle State Tree (WDB-0004)
```

## 3. Database Adapter Requirements

### 3.1 PostgreSQL Adapter
- Capture via PL/pgSQL Triggers (`src/postgres/`) or native logical decoding WAL stream (`src/wal/`, `WDB-0010`).

### 3.2 MySQL Adapter
- Capture via MySQL Binary Log (binlog) in `ROW` format (`binlog_format=ROW`).
- Maps `WRITE_ROWS_EVENT` $\to$ `INSERT (1)`, `UPDATE_ROWS_EVENT` $\to$ `UPDATE (2)`, `DELETE_ROWS_EVENT` $\to$ `DELETE (3)`.
- Reconstructs primary keys using table metadata and maps to canonical primary key binary tuples (`WDB-0002`).

### 3.3 SQLite Adapter
- Capture via SQLite preupdate hook (`sqlite3_preupdate_hook`) or update hook (`sqlite3_update_hook`) / change counter triggers.
- Translates rowid / table primary keys into canonical binary tuples (`WDB-0002`).
- Enforces RFC 8785 JSON canonicalization for column values.
