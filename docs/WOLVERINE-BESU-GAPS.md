# WolverineDB — Hyperledger Besu Implementation Gaps & Action Plan

**Document Status**: Implementation Gap Registry  
**Auditor**: Systems Architecture Team  
**Date**: August 2026

---

## Gap 1: Cloud KMS Providers Contain Silent HMAC Fallbacks
- **Severity**: HIGH (Security & Architectural Integrity)
- **Why it exists**: Written as a quick development fallback when neither a live KMS client nor a mock KeyObject is supplied.
- **Architectural Impact**: Violates the fail-closed security rule ("If KMS fails: NO fallback. NO HMAC. NO silent software signing. Return an explicit failure").
- **Smallest Correct Fix**: Remove `crypto.createHmac(...)` in `AwsKmsSigningProvider.ts` and `GcpKmsSigningProvider.ts`. Throw `WolverineError(WolverineErrorCode.KMS_OUTAGE, 'KMS client unconfigured or unavailable')` immediately.

---

## Gap 2: Live Besu Node vs Mock RPC Transparency in Demo & Client
- **Severity**: MEDIUM (Implementation Truth & Clarity)
- **Why it exists**: `demo/besu_demo.ts` uses an inline `mockRpc` function because Docker was not running.
- **Architectural Impact**: Gives the appearance of live Besu block production and transaction inclusion when it was simulated.
- **Smallest Correct Fix**:
  1. Have `demo/besu_demo.ts` attempt to connect to `http://127.0.0.1:8545` first.
  2. If unreachable, explicitly log: `[WARN] Besu RPC at 127.0.0.1:8545 unreachable. Docker daemon offline. Falling back to local development simulation...`
  3. Clearly distinguish simulated blocks from live blockchain receipts.

---

## Gap 3: PostgreSQL CDC Ingestion Requires Live Database Service
- **Severity**: LOW / EXPECTED (Integration Dependency)
- **Why it exists**: `PgLogicalClient` contains real SQL and `pgoutput` wire protocol decoding, but without a running PostgreSQL database service, CDC requires test mocks.
- **Architectural Impact**: Expected for unit test environments; integration tests must start PostgreSQL via Docker or local service.
- **Smallest Correct Fix**: Document PostgreSQL prerequisite and provide mock stream test fixtures alongside real connection tests.

---

## Gap 4: Legacy TypeScript BFT Consensus Files Retained in Source Tree
- **Severity**: LOW (Architectural Hygiene)
- **Why it exists**: Retained so that 120+ legacy unit tests continue to validate cryptographic and invariant behaviors.
- **Architectural Impact**: Could create confusion regarding which consensus engine is authoritative.
- **Smallest Correct Fix**: Add docstrings and header notices to `src/trust_network/consensus.ts` and `src/trust/quorum_certificate.ts` marking them explicitly as `// DEPRECATED FOR PRODUCTION — REFERENCE / TEST FIXTURE ONLY. Authoritative consensus is Hyperledger Besu QBFT.`
