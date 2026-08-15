# Crash-Safe Validator Journals & State Replay

This document details how validator journals persist append-only attestation entries with fsync durability and survive process crashes and power loss.

## Recovery Properties
1. **Truncated Tail Recovery**: Recovers up to the last valid journal record without failing closed.
2. **Corrupted Record Defense**: Fails closed if intermediate bytes are modified or forged.
3. **Snapshot Replay Engine**: Combines clean baseline snapshots with journal suffixes to deterministically recompute the 32-byte Merkle State Root.
