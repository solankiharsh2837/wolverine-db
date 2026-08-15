# Verified State Frontier Calculation

The **Verified State Frontier** represents the highest point in database history that is provably authentic and free from tampering.

## Core Principle: No Blind Old Rollbacks

Traditional disaster recovery systems blindly rollback to the last backup snapshot, destroying hours or days of legitimate user transactions that occurred between the snapshot and the attack.

WolverineDB v0.6 reconstructs state forward-additively:
$$\text{Reconstructed State} = \text{Verified Checkpoint} + \sum \text{Authorized Changes} - \sum \text{Compromised Changes}$$

## The 7 Frontier Invariants

1. **Verified Base Checkpoint**: Starting checkpoint matches external WORM vault.
2. **Blockchain Anchor Consensus**: Checkpoint digest committed to public chains.
3. **Continuous Hash Chain**: No broken SHA-256 links.
4. **Strict Sequence Monotonicity**: No missing sequences or gaps.
5. **Execution Provenance**: Authentic session and actor metadata.
6. **Authorization Conformance**: Valid maintenance window and change tickets.
7. **Merkle Convergence**: Recomputed Merkle tree matches deterministic row states.
