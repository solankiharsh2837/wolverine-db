# Trust Time & Verifiable Temporal Ordering

Wolverine establishes a formal decoupling between internal **Database Time** and network **Trust Time**.

## The Two Timelines

```text
DATABASE TIME (Local Commit Sequence)
     │
     │ commitSeq
     ▼
1842 ──────────────────────────────────────────► 1917


TRUST TIME (Wolverine Network Consensus Progression)
     │
     │ ledgerSeq
     ▼
8271 ──────────────────────────────────────────► 8420
```

## Why Trust Time Matters
Wall-clock timestamps can be skewed, spoofed, or manipulated by NTP tampering.
**Trust Time** provides a strictly monotonic, consensus-attested sequence ($S_{\text{ledger}}$) proving that a given database state existed prior to that global ledger sequence.
