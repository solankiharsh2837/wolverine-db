# WDB-0003: Hash chain

Status: Normative Specification (v0.1 Frozen).

Define `H(x) = SHA-256(x)`. Domain tags are UTF-8 ASCII bytes without NUL terminators.

## Predecessors & Genesis

- The genesis predecessor hash is 32 zero bytes (`0x00` * 32).
- Implementations MUST compare all 32 bytes and MUST reject malformed or missing predecessor material rather than substituting zero.

## Stream Partitioning & Global Ordering

- v0.1 enforces a single global linear change stream per protected database scope.
- Order is established by the `Wolverine Commit Sequence`, a monotonically increasing 64-bit sequence assigned inside PostgreSQL transaction commit boundaries via explicit sequence locking (`wolverine_sys.commit_seq`).
- Rollbacks and aborted transactions leave zero gaps and emit zero change records.

## Hash Formulas

- For an ordered committed change record:
  `change_hash = H("WDB:CHANGE:v1" || u32be(len(record_bytes)) || record_bytes || previous_hash)`
- For a version record:
  `version_hash = H("WDB:VERSION:v1" || u32be(len(version_bytes)) || version_bytes || parent_version_hash)`

All hash comparisons MUST use fixed-width, constant-time comparison functions to prevent timing side-channel vulnerabilities.
