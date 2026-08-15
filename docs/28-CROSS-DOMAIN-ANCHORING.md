# Cross-Domain Verification

In WolverineDB v0.3, integrity is verified across three orthogonal trust planes:

1. **Local Database Engine** (PostgreSQL / MySQL / SQLite): Maintains live state and fast transactional mutation history in `wolverine_sys`.
2. **External Object Vault** (Amazon S3 Object Lock / WORM appliance): Preserves full historical checkpoints and change records off-site under immutable compliance hold.
3. **Public Cryptographic Anchors** (Ethereum, Arbitrum, Base, Bitcoin): Commits 32-byte Checkpoint Digests to public, globally distributed blockchain networks.

## Threat Analysis & Cross-Domain Detection

```
Database
   │
   ▼
Merkle Root = DEAD...  (Attacker altered local rows)
                ❌
WORM Vault = 91BC...   (Intact independently)
                ❌
Ethereum   = 91BC...   (Intact publicly)
                ❌

       RESULT: STATE DIVERGENCE DETECTED
```

Even if an attacker compromises internal DBA credentials and internal AWS access keys simultaneously, the public blockchain anchor provides immutable proof of the authentic historical commitment.
