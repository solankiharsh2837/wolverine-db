# Universal Multi-Database Adapters

WolverineDB v0.3 extends change capture beyond PostgreSQL to MySQL and SQLite without altering cryptographic core semantics.

## Architectural Invariant

All database adapters terminate at the standard `ChangeRecordData` interface:

```
PostgreSQL (WAL/Triggers) ──┐
MySQL (Row-Format Binlog) ──┼──► Capture Normalizer ──► Canonical Binary (WDB-0002) ──► SHA-256 Chain
SQLite (Hooks/CDC)        ──┘
```

## Adapter Matrix

| Database Engine | Capture Mechanism | Transaction Isolation | Replay Protection |
| :--- | :--- | :--- | :--- |
| **PostgreSQL** | Logical Decoding (WAL) / Triggers | Strict Monotonic LSN / `commit_seq` | Confirmed Flush LSN |
| **MySQL** | Row-Based Binlog (`binlog_format=ROW`) | Monotonic GTID / Binlog position | Binlog Position Offset |
| **SQLite** | Preupdate Hooks / CDC Triggers | Single-writer serialized transactions | Commit sequence counter |
