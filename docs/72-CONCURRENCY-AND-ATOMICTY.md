# WolverineDB Concurrency and Atomicity Architecture

---

## 1. The Trust Ledger Concurrency Hazard

In distributed trust architectures, multiple client requests arrive asynchronously at the gateway. If two commitments execute `appendRecord()` concurrently on the persistent ledger without serialization:

```text
Request A (t0) ──> reads head H100 ──> constructs Seq 101A ──> writes storage ──> head = H101A
Request B (t0) ──> reads head H100 ──> constructs Seq 101B ──> writes storage ──> head = H101B (FORK!)
```

This creates a split-brain condition where two differing commitments share sequence 101, corrupting the hash chain.

---

## 2. The Solution: Linearized Mutex Queue

`PersistentTrustLedger` encapsulates the entire transaction—reading head, computing digest, persisting to disk, and updating in-memory state—within an atomic promise queue:

```typescript
const executeAppend = async (): Promise<TrustLedgerRecord> => {
  const ledgerSeq = BigInt(this.records.length + 1);
  const previousRecordDigest = this.chainHead;
  const recordDigest = computeLedgerRecordDigest(previousRecordDigest, ledgerSeq, payload);
  const record: TrustLedgerRecord = { ledgerSeq, previousRecordDigest, recordDigest, ... };

  await this.storage.writeRecord(record);

  this.records.push(record);
  this.recordDigests.push(recordDigest);
  this.chainHead = recordDigest;
  return record;
};

const nextAppend = this.appendMutex.then(executeAppend, executeAppend);
this.appendMutex = nextAppend;
return nextAppend;
```

---

## 3. Checkpoint Store TOCTOU Elimination

`LocalCheckpointStore` enforces atomic creation at the kernel boundary:

```typescript
await fs.writeFile(filePath, serialized, { encoding: 'utf8', mode: 0o444, flag: 'wx' });
```

If the file already exists, the kernel atomically returns `EEXIST`, triggering an idempotent verification read instead of overwriting.
