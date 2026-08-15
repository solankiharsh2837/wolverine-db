# Native PostgreSQL WAL Capture

WolverineDB v0.2 integrates native PostgreSQL Write-Ahead Log (WAL) logical decoding to capture database mutations asynchronously and out-of-band without overhead on primary application transaction paths.

## Logical Replication Workflow

```
PostgreSQL WAL
     │
     ▼
Logical Replication Slot (pg_create_logical_replication_slot)
     │
     ▼
Output Plugin (pgoutput / test_decoding)
     │
     ▼
Wolverine WAL Decoder
     │
     ▼
Capture Normalizer (RFC 8785 JSON + Canonical Binary Primary Key)
     │
     ▼
Canonical Change Stream (WDB-0001 / WDB-0002)
     │
     ▼
SHA-256 Hash Chain (WDB-0003)
```

## Advantages Over Triggers

1. **Zero Write Overhead**: Eliminates trigger invocation overhead and synchronous insertion into internal metadata tables during user transactions.
2. **Superuser Bypass Immunity**: Even if an administrative user disables session triggers (`SET session_replication_role = 'replica'`), committed mutations continue to be recorded in the WAL and consumed by WolverineDB.
3. **Bulk Load Efficiency**: Handles high-throughput batch operations without locking contention on `wolverine_sys.commit_seq`.

## LSN Acknowledgment & Crash Safety

- The capture worker maintains an in-memory sliding buffer of in-flight transactions.
- LSN feedback is sent to PostgreSQL only after transaction changes are securely written and hashed into the local chain or anchored externally.
- On process crash or network failure, replication resumes from the last confirmed flush LSN with deterministic deduplication.
