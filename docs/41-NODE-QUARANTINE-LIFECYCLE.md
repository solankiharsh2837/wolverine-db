# Node Quarantine Lifecycle & Evidence Preservation

When a node exhibits Byzantine behavior, the federation isolates it without discarding historical evidence.

## Trigger Conditions

1. **Invalid Signature**: Event signature does not match registered public key.
2. **Divergent Checkpoint**: Node reports a Merkle root differing from the $M$-of-$N$ consensus majority.
3. **Sequence Mismatch**: Node skips sequence numbers or submits conflicting previous event hashes.
4. **Anomalous Recovery**: Node attempts to trigger unapproved recovery mutations.

## Forensic Preservation

Upon quarantine, the federation records:
- `lastValidEventSequence` and `lastValidEventHash`.
- `lastValidCheckpointId`.
- The raw triggering payload and failure classification.

All valid historical commits emitted by the node prior to quarantine remain cryptographically intact.
