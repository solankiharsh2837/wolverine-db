# WolverineDB (v0.1.0 Stable)

WolverineDB is an open-source integrity and recovery framework for existing databases. It records authorized changes as an append-only, cryptographically verifiable history; derives state commitments; detects divergence; and supports evidence-preserving, approval-gated selective recovery.

PostgreSQL remains the live system of record. WolverineDB sits alongside PostgreSQL, enforcing deterministic binary serialization, domain-separated SHA-256 hash chains, Merkle state checkpoints, and Ed25519 policy-signed recovery workflows.

---

## Key Features (v0.1.0)

- **Deterministic Binary Encoding (WDB-0002)**: Strict 9-byte binary envelope, RFC 8785 JSON canonicalization (UTF-16 code unit key sorting), strict decimal grammar, and length-delimited primary key tuples.
- **Append-Only Hash Chains (WDB-0003)**: Monotonic transaction commit sequence numbers (`wolverine_sys.commit_seq`) and domain-separated SHA-256 change hash chains (`"WDB:CHANGE:v1"`).
- **Merkle Checkpoint Verification (WDB-0004)**: Lexicographically sorted leaf keys, Merkle inclusion proofs, and fixed empty-tree root constant (`SHA256("WDB:EMPTY_ROOT:v1")`).
- **Cryptographic Policy Approval Gating (WDB-0006)**: Selective recovery requires a valid Ed25519 signature over a canonical approval envelope, enforcing separation of duties, trusted approver verification, timestamp expiration, and replay nonce protection.
- **CLI & SDK (`wdb`)**: Public TypeScript SDK and CLI tool (`wdb init`, `status`, `verify`, `checkpoint`, `recover`) with human-readable and `--json` machine outputs.

---

## Quick Start & Usage

### 1. Installation & Build

```bash
npm install
npm run build
npm test
```

### 2. TypeScript SDK Example

```typescript
import { WolverineDB, generateRecoveryProposal } from 'wolverine-db';

// 1. Connect to WolverineDB
const wdb = await WolverineDB.connect({
  connectionString: 'postgresql://postgres:postgres@localhost:5432/mydb',
  protectedTables: ['public.users', 'public.accounts'],
  trustedApproversHex: ['d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'],
});

// 2. Verify Database Integrity
const report = await wdb.verify('public.users');
console.log('Verification Report:', report.status); // VALID | MERKLE_ROOT_MISMATCH | CHANGE_HASH_MISMATCH

// 3. Generate Non-Destructive Recovery Proposal
const proposal = generateRecoveryProposal(
  'incident-uuid-1234',
  'public.users',
  'target-version-uuid-5678',
  [
    {
      tableName: 'public.users',
      primaryKeyTuple: Buffer.from([1]),
      fieldName: 'email',
      newValue: 'restored@example.com',
    },
  ],
  'operator1@example.com'
);
```

### 3. CLI (`wdb`) Usage

```bash
# Check database protection status
npx wdb status

# Verify database integrity
npx wdb verify --scope public.users --json

# Generate Merkle state checkpoint
npx wdb checkpoint --scope global --json
```

---

## Benchmark Methodology & Environmental Caveats

> [!NOTE]
> Benchmark results represent performance within our tested synthetic suite and in-memory test environment. They demonstrate sub-millisecond cryptographic and pipeline efficiency, but should be evaluated against your target PostgreSQL database hardware, WAL fsync configuration, and production transaction size before deployment.

- **Binary Encoding**: ~198,317 records/sec (~5.0 $\mu$s / record)
- **Binary Decoding**: ~378,993 records/sec (~2.6 $\mu$s / record)
- **SHA-256 Hash Chain**: ~195,672 hashes/sec (~5.1 $\mu$s / hash)
- **Merkle Tree (10k leaves)**: 65.54 ms
- **Ed25519 Approval Verification**: ~5,742 approvals/sec (~174 $\mu$s / verification)
- **End-to-End Pipeline**: **54,459 tx/sec** with an average latency overhead of **0.0184 ms (18.4 $\mu$s)** per transaction.

---

## Security & Threat Boundaries

- **Supported Protections**: Detects unauthorized application-level mutations, row tampering, history deletion, out-of-order changes, invalid Merkle roots, and forged recovery requests.
- **DBA Boundaries**: Change capture triggers protect against application-level modifications. A privileged DBA bypassing triggers or directly editing `wolverine_sys` tables is detected by offline Merkle tree verification against external checkpoints.
- **Non-Destructive Invariant**: Cryptographic hash mismatches **never** trigger automatic destructive rollbacks. Recovery is strictly approval-gated and non-destructive.

---

## License

MIT License.
