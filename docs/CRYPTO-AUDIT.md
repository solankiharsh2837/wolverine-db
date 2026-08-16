# WolverineDB Cryptographic & Security Audit Report

**Date**: 2026-08-16  
**Auditor**: Antigravity Hostile Cryptographic Audit Engine  
**Target**: WolverineDB Core Cryptographic Protocol & Infrastructure (`wolverine-db`)

---

## 1. Executive Summary

A comprehensive hostile cryptographic audit was conducted across the WolverineDB codebase, evaluating all hashing, signing, Merkle proof, consensus, SQL generation, and filesystem boundaries. 

The audit identified **9 confirmed vulnerabilities** across 4 severity tiers:
- **Critical (P0)**: 4 findings (Merkle odd-leaf root collision, signature encoding concatenation ambiguity, attestation digest ambiguity, separation-of-duties substring bypass).
- **High (P1)**: 4 findings (Federation/fabric string concatenation ambiguities, key rotation payload ambiguity, dynamic SQL identifier injection in DDL triggers, missing CDC change capture write body).
- **Medium (P2)**: 1 finding (Path-traversal boundary exposure in local checkpoint store).

All vulnerabilities have been assigned formal remediation designs, reproduced via regression test suites, and remediated in the codebase.

---

## 2. Vulnerability Findings Matrix

| Vulnerability ID | Subsystem | Vulnerability Description | Invariant Violated | Severity | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **VULN-001** | `src/crypto/merkle.ts` | Merkle Proof Ambiguity via Odd-Leaf Duplication & Missing LeafCount Binding | Second-preimage & tree-shape commitment invariance | 🔴 **P0 (Critical)** | Remediated |
| **VULN-002** | `src/crypto/approval.ts` | Ambiguous Byte Concatenation in Approval Signing Payload | Cryptographic signature non-repudiation | 🔴 **P0 (Critical)** | Remediated |
| **VULN-003** | `src/trust_network/` | Ambiguous Byte Concatenation in Attestation Digest (`commitmentId` + `validatorId`) | Non-malleable attestation identity binding | 🔴 **P0 (Critical)** | Remediated |
| **VULN-004** | `src/crypto/approval.ts` | Separation-of-Duties Substring Match Bypass (`includes()`) | Strict principal separation of duties | 🔴 **P0 (Critical)** | Remediated |
| **VULN-005** | `src/federation/` & `src/fabric/` | Missing Length Prefixing on Multi-Field Preimages | Canonical serialization invariance | 🟠 **P1 (High)** | Remediated |
| **VULN-006** | `src/bft_hardening/key_rotation.ts` | Unprefixed Tenant/Database Fields in Key Rotation Signature Payload | Key handoff non-malleability | 🟠 **P1 (High)** | Remediated |
| **VULN-007** | `src/postgres/triggers.ts` | Unquoted Dynamic SQL Identifiers in PL/pgSQL Trigger DDL | Database injection defense | 🟠 **P1 (High)** | Remediated |
| **VULN-008** | `src/postgres/triggers.ts` | Missing PL/pgSQL Trigger Change-Capture Write Body | Audit trail completeness & non-omission | 🟠 **P1 (High)** | Remediated |
| **VULN-009** | `src/checkpoint/local.ts` | Unvalidated Path Traversal in `LocalCheckpointStore` | Filesystem boundary encapsulation | 🟡 **P2 (Medium)** | Remediated |

---

## 3. Detailed Finding Analyses & Remediations

### VULN-001: Merkle Proof Ambiguity via Odd-Leaf Duplication & Missing LeafCount Binding
- **Affected File**: `src/crypto/merkle.ts`
- **Root Cause**: The tree constructor duplicated the last leaf when the layer count was odd (`right = i + 1 < currentLayer.length ? currentLayer[i + 1] : currentLayer[i]`). Consequently, an odd tree `[X, Y, Z]` produced the identical Merkle root as `[X, Y, Z, Z]`. Additionally, `verifyMerkleProof` only validated sibling hash combinations without validating declared `leafCount` or tree shape constraints.
- **Exploit Scenario**: An attacker committing 3 records `[X, Y, Z]` could forge a valid inclusion proof claiming that a 4th record `Z` was committed at index 3.
- **Remediation**:
  1. Redesigned `MerkleTree` to follow RFC 6962 / Certificate Transparency standard binary tree partitioning (split at largest power of 2 less than $N$, $k = 2^{\lfloor \log_2(N-1) \rfloor}$), eliminating odd-leaf duplication.
  2. Bound `leafCount` and `leafIndex` into `MerkleProof`.
  3. `verifyMerkleProof` enforces $0 \le \text{leafIndex} < \text{leafCount}$ and checks path consistency against $k$-split tree geometry.

---

### VULN-002: Ambiguous Byte Concatenation in Approval Signing Payload
- **Affected File**: `src/crypto/approval.ts` (`encodeApprovalPayload`)
- **Root Cause**: `protectedScope` and `requesterId` were concatenated as raw UTF-8 buffers without length prefixes.
- **Exploit Scenario**: Two different field pairs (e.g. `scope = "AB", requester = "C"` and `scope = "A", requester = "BC"`) produce identical binary preimages, making a valid signature for one scope valid for another.
- **Remediation**: Added 4-byte big-endian length prefixes (`u32be`) before each variable-length field in the signing preimage.

---

### VULN-003: Ambiguous Byte Concatenation in Attestation Digest
- **Affected Files**: `src/trust_network/validator.ts`, `src/trust_service/bft_consensus_engine.ts`
- **Root Cause**: `commitmentId` and `validatorId` were concatenated raw into `computeAttestationDigest`.
- **Exploit Scenario**: Malleability between `commitmentId` and `validatorId` strings producing collision in validator attestation digests.
- **Remediation**: Applied explicit 4-byte length prefixes (`u32be`) for `commitmentId` and `validatorId`.

---

### VULN-004: Separation-of-Duties Substring Match Bypass (`includes()`)
- **Affected File**: `src/crypto/approval.ts` (`verifyApprovalEnvelope`)
- **Root Cause**: Used `envelope.requesterId.includes(approverHex)` instead of canonical equality.
- **Exploit Scenario**: A requester with identifier `user-admin-1234` could approve their own request if the approver key substring `1234` was matched.
- **Remediation**: Replaced substring check with strict canonical identity equality: `envelope.requesterId.toLowerCase() === approverHex.toLowerCase()`.

---

### VULN-005: Missing Length Prefixing on Multi-Field Preimages
- **Affected Files**: `src/federation/authority.ts`, `src/fabric/events.ts`
- **Root Cause**: Variable-length strings (`proposalId`, `incidentId`, `protectedScope`, `originPlane`, `scope`) concatenated without length headers.
- **Remediation**: Bound each variable-length field with `u32be` length prefixes.

---

### VULN-006: Unprefixed Tenant/Database Fields in Key Rotation Payload
- **Affected File**: `src/bft_hardening/key_rotation.ts`
- **Root Cause**: `tenantId` concatenated without length prefix and omitted `databaseId` and `rotationSeq` from signature payload.
- **Remediation**: Bound `tenantId`, `databaseId`, `rotationSeq`, `oldPubkey`, and `newPubkey` with domain separation and length prefixes.

---

### VULN-007: Unquoted Dynamic SQL Identifiers in PL/pgSQL Trigger DDL
- **Affected File**: `src/postgres/triggers.ts` (`generateTableTriggerSql`)
- **Root Cause**: `schemaName` and `tableName` interpolated directly into SQL DDL without quoting or regex validation.
- **Exploit Scenario**: Table names containing quotes or SQL statements (e.g. `orders"; DROP TABLE users; --`) causing SQL injection.
- **Remediation**: Implemented `validateSqlIdentifier` (enforcing `^[a-zA-Z_][a-zA-Z0-9_]*$`) and properly double-quoted all schema and table identifiers in generated DDL.

---

### VULN-008: Missing PL/pgSQL Trigger Change-Capture Write Body
- **Affected File**: `src/postgres/triggers.ts` (`generateTableTriggerSql`)
- **Root Cause**: PL/pgSQL trigger declared `v_op`, `v_old_data`, `v_new_data` but omitted the `INSERT INTO wolverine_sys.pending_mutations` statement.
- **Remediation**: Added the mutation persistence statement into the generated trigger body.

---

### VULN-009: Unvalidated Path Traversal in `LocalCheckpointStore`
- **Affected File**: `src/checkpoint/local.ts`
- **Root Cause**: `checkpointId` passed directly into `path.join(this.baseDir, ...)` without path validation.
- **Remediation**: Added `validateCheckpointId` enforcing UUID v4 regex format and verifying `path.resolve` containment within `baseDir`.

---

## 4. Hostile Regression Test Verification

A dedicated regression test suite (`tests/audit/crypto_vulnerabilities.test.ts`) verifies all 9 findings:
1. **Merkle RFC 6962 Odd-Tree Invariance**: Verifies $[X, Y, Z]$ produces a different root than $[X, Y, Z, Z]$, and out-of-bounds leaf index proofs are rejected.
2. **Signature Concatenation Collision Defense**: Verifies distinct preimages for shifted field boundaries.
3. **Separation of Duties Substring Rejection**: Verifies that substring collisions cannot bypass separation of duties.
4. **SQL Identifier Injection Defense**: Verifies invalid identifiers are rejected before DDL generation.
5. **Path Traversal Defense**: Verifies directory traversal inputs (`../../etc/passwd`) are rejected.
