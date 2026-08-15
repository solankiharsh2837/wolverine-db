# WDB-0014: Capture Equivalence Testing

Status: Normative Specification (v0.2 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification establishes the normative testing framework for validating 100% semantic and cryptographic equivalence between:
1. **Trigger-based capture** (PL/pgSQL triggers inside PostgreSQL transactions)
2. **WAL-based capture** (PostgreSQL logical replication slot decoding)

```
        PostgreSQL Transaction Corpus
               /             \
              /               \
       Trigger Capture     WAL Capture
             │                 │
             ▼                 ▼
     Capture Normalizer  Capture Normalizer
             │                 │
             ▼                 ▼
     Canonical CHANGE     Canonical CHANGE
             │                 │
             ▼                 ▼
          SHA-256           SHA-256
             \                 /
              \               /
            Deterministic Comparator
                     │
             [PASS / FAIL MATRIX]
```

## 2. Equivalence Criteria

Two capture streams generated from identical transactional operations MUST satisfy the following strict equivalence matrix:

| Verification Stage | Mismatch Condition | Permissible Divergence | Result |
| :--- | :--- | :--- | :--- |
| **Transaction Sequence** | Transaction count or order mismatch | Zero | **FAIL** |
| **Mutation Operation** | Operation type differs (`INSERT`/`UPDATE`/`DELETE`) | Zero | **FAIL** |
| **Primary Key Tuple** | Binary record identifier differs (`WDB-0002`) | Zero | **FAIL** |
| **Canonical Payload** | RFC 8785 normalized field sets differ | Zero | **FAIL** |
| **Domain Hash** | SHA-256 change hash differs (`WDB-0003`) | Zero | **FAIL** |
| **Merkle State Root** | Merkle tree state root differs (`WDB-0004`) | Zero | **FAIL** |

## 3. Deterministic Corpus Specification

Equivalence testing suites MUST execute against a multi-operation deterministic corpus comprising:
1. Standard single-row `INSERT`, `UPDATE`, and `DELETE` statements.
2. Multi-row batch mutations.
3. Complex JSONB and array column transformations.
4. Decimal/Numeric fields with varying trailing zeros (validating canonical decimal normalization).
5. UTF-8 multi-byte strings and international character sets.
6. Explicit transaction aborts and rollbacks (verifying both engines emit zero changes).
7. Interleaved concurrent transactions with varying commit ordering.

## 4. Automation & Certification

An implementation of WolverineDB v0.2 MUST provide an automated equivalence runner (`tests/equivalence/`) that asserts bit-for-bit equivalence over test corpora before WAL capture can be certified for production deployment.
