# Reconstruction Proof Graph & Proof Paths

The **Reconstruction Proof Graph** builds an unbroken chain of evidence verifying why each individual mutation is permitted to be included in the reconstructed state.

## Proof Graph Topology

```text
CHECKPOINT #100 (WORM / External Trust Validated)
  │
  ├── seq 101 ── valid auth + valid provenance ──> PRESERVE
  │
  ├── seq 102 ── valid auth + valid provenance ──> PRESERVE
  │
  ├── seq 103 ── compromised actor identity   ──> EXCLUDE
  │
  ├── seq 104 ── valid independent proof      ──> PRESERVE
  │
  ├── seq 105 ── valid independent proof      ──> PRESERVE
  │
  ├── seq 106 ── unauthorized scope violation ──> EXCLUDE
  │
  ├── seq 107 ── valid proof + safe deps      ──> PRESERVE
  │
  └── seq 108 ── valid proof + safe deps      ──> PRESERVE
```

The entire graph is hashed into a 32-byte `reconstructionGraphDigest` committed to the final State Recovery Certificate V2.
