# WolverineDB Release Roadmap

## v0.1.0 (Completed - Stable Release)
- Deterministic canonical binary encoding (WDB-0002) with RFC 8785 JSON canonicalization, strict decimal normalization, and primary key tuple representations.
- SHA-256 domain-separated hash chains (WDB-0003) and global sequence locks (`wolverine_sys.commit_seq`).
- Merkle state checkpoints (WDB-0004) with fixed empty-tree root constants.
- Ed25519 policy-signed approval envelopes (WDB-0006) for non-destructive selective recovery.
- PostgreSQL change capture schema (`wolverine_sys`), verifier engine, and TypeScript SDK + `wdb` CLI tool.
- Hostile security audit suite (16 attack vectors), 7-level catastrophic recovery escalation, fuzzing suite, and performance benchmarks.

## v0.2.0 (Next Major Release)
- Production PostgreSQL WAL / logical decoding integration.
- External immutable checkpoint storage (S3 / WORM buckets).
- Enhanced authorization provenance and ticket provider integrations.
- Operational observability (Prometheus / OpenTelemetry metrics).
- Advanced selective state reconstruction tooling.

## v0.3.0
- External blockchain / EVM anchoring.
- Additional database adapters (MySQL / SQLite).

## v0.4.0
- Advisory Sentinel / AI anomaly intelligence layer (policy-constrained, sitting above deterministic cryptographic core).

## v1.0.0
- Production-grade stable protocol, full enterprise compatibility commitments, and third-party security audit certification.
