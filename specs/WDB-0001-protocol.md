# WDB-0001: Protocol

Status: Normative Specification (v0.1 Frozen). The normative terms **MUST**, **MUST NOT**, and **SHOULD** are used as requirements.

A protected transaction MUST produce zero history records when rolled back and one ordered change stream when committed. A ChangeRecord MUST identify its format version, record type, transaction identifier, version identifier, commit timestamp, protected table object, primary key identifier tuple, mutation operation, field set, authorization provenance envelope, and predecessor change hash. A version MUST reference its immediate parent and MUST NOT be edited after commit.

## Record Types

Numeric values for record types:
- `1`: `CHANGE`
- `2`: `VERSION`
- `3`: `CHECKPOINT`
- `4`: `ANCHOR`
- `5`: `INCIDENT`
- `6`: `RECOVERY`

## Mutation Operations

Numeric values for mutation operations in `CHANGE` records:
- `1`: `INSERT`
- `2`: `UPDATE`
- `3`: `DELETE`

Implementations MUST reject unknown record types, unknown mandatory fields, and malformed field payloads. Unknown optional fields MUST be rejected unless an explicit future format profile permits them.

Conformance requires deterministic encoding under WDB-0002 and exact binary match with `specs/TEST-VECTORS.md`.
