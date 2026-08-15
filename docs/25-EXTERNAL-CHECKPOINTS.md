# External Checkpoint Storage & Independent Evidence

In WolverineDB v0.2, proof of database integrity is externalized into immutable storage tiers, separating the live database of record from the cryptographic verification substrate.

## Storage Backends

1. **Local File Store (`LocalCheckpointStore`)**:
   - Stores serialized checkpoint records to designated directories.
   - Enforces read-only permissions after writes.
   - Ideal for local test suites and lightweight single-node deployments.

2. **Amazon S3 / S3-Compatible (`S3CheckpointStore`)**:
   - Stores checkpoints in Amazon S3, Cloudflare R2, or MinIO buckets.
   - Leverages S3 Object Lock in Compliance Mode to make historical checkpoints mathematically and administratively immutable.
   - Checkpoint SHA-256 digest is attached as metadata and verified on read.

3. **WORM Store (`WORMCheckpointStore`)**:
   - Write-Once-Read-Many storage appliance adapter.
   - Guarantees strict non-repudiation and hardware-level append-only retention.

## Anchoring & Split-Brain Detection

An attacker who gains superuser access to PostgreSQL may attempt to alter live tables, drop history tables, or forge internal timestamps. However, because checkpoints are anchored externally:

```
[PostgreSQL Database]                  [External S3 Object Lock]
Live State: Root c31f...   ──(Mismatch)──► Checkpoint #42: Root 7a91...
```

The offline verifier compares the live database state root against the externally retained checkpoint, identifying state divergence immediately with zero false negatives.
