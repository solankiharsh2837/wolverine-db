# WolverineDB // Testing & Verification Suite

> **Source Code is Authoritative.**  
> This document specifies the automated test architecture, test suites, adversarial attack vectors, and validation commands for **WolverineDB v1.3.0**.

---

## 1. Test Suite Overview

WolverineDB utilizes **Vitest** for fast, deterministic unit, integration, property-based, and adversarial test execution.

- **Total Test Files**: 91 test files
- **Total Unit & Property Tests**: 222 tests
- **Execution Time**: ~9–11 seconds
- **Pass Rate**: 100% (0 failures)

---

## 2. Test Suite Classification

| Suite Category | Directory / Files | Focus & Scope |
| :--- | :--- | :--- |
| **Recovery & Replay** | `tests/recovery/`, `tests/catastrophic_recovery.test.ts` | State reconstruction, durable nonce uniqueness, WAL replay |
| **BFT & Quorums** | `tests/trust_network/`, `tests/v1_service/` | Byzantine safety theorems, equivocation defense, quorum failure |
| **Gateway Hardening** | `tests/runtime/gateway_binding.test.ts`, `gateway_auth.test.ts` | Boundary signer authentication, ledger record binding (Issues #2 & #3) |
| **Sentinel & Policy** | `tests/sentinel/policy_gate.test.ts`, `baseline.test.ts` | Scope bounding, TOCTOU immutability, blast radius caps (Issue #4) |
| **Adversarial & Fuzz** | `tests/adversarial/`, `tests/fuzz.test.ts` | Forged events, key compromise, corrupted signatures, split federation |
| **Database Adapters** | `tests/postgres_integration.test.ts`, `adapters/` | PostgreSQL logical replication, schema creation, error 23505 handling |
| **Anchoring & EVM** | `tests/anchors/`, `tests/checkpoint/` | WORM stores, EVM anchor confirmations, reorg resilience |
| **Cryptography** | `tests/audit/crypto_vulnerabilities.test.ts`, `binary.test.ts` | Merkle tree invariants, canonical JSON serialization, timing-safe compare |

---

## 3. Standard Verification Commands

```bash
# 1. Run full test suite across all 91 test files
npm test

# 2. Run specific subsystem test file
npx vitest run tests/runtime/gateway_auth.test.ts
npx vitest run tests/sentinel/policy_gate.test.ts
npx vitest run tests/recovery/durable_nonce.test.ts

# 3. Type check the entire TypeScript codebase
npm run build
```
