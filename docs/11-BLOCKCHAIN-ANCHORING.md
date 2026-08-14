# Blockchain anchoring

An anchor commits a checkpoint hash and Merkle root, not database rows or change payloads. The flow is `Database -> Merkle Root -> Checkpoint -> external commitment`. Anchoring is optional in v0.1 and never lies on the database write path.

An unavailable chain records a pending/failed anchor operation and does not prevent local verification. Provider, chain, transaction format, finality threshold, and retry policy are **UNRESOLVED**; EVM support is planned after core protocol stability.
