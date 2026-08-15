# Persistent Ledger & Incremental Merkle State Root

The Trust Ledger commits every finalized sequence to persistent storage and computes an incremental Merkle tree over all sequence record digests.

## State Root Properties
- **Incremental Root**: As sequence records are committed ($S_1, S_2, \dots, S_n$), the root is recalculated deterministically.
- **Crash Consistency**: On node restart, journal entries are replayed and state roots recomputed.
- **State Root Attestation**: Auditors can verify whole-ledger integrity by comparing single 32-byte roots.
