# WolverineDB // Known Issues & Security Audit Status

> **Source Code is Authoritative.**  
> This living document tracks all security audit findings, their severity, root causes, remediations, test coverage, and upstream GitHub Pull Requests for **WolverineDB v1.3.0**.

---

## Security Audit Findings Summary

| Issue ID | Vulnerability Summary | Component | Severity | Upstream PR | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Issue #1** | Replay protection not durable (in-memory `Set<string>` used instead of PostgreSQL schema) | Recovery Engine | Medium | **[PR #5](https://github.com/solankiharsh2837/wolverine-db/pull/5)** | ✅ Resolved |
| **Issue #2** | Gateway returns ledger record not bound to ingested commitment (`records[length-1]!`) | Trust Gateway | Medium | **[PR #6](https://github.com/solankiharsh2837/wolverine-db/pull/6)** | ✅ Resolved |
| **Issue #3** | Gateway does not authenticate commitment signer at network ingress boundary | Ingress Auth | Low-Med | **[PR #7](https://github.com/solankiharsh2837/wolverine-db/pull/7)** | ✅ Resolved |
| **Issue #4** | Policy gate TOCTOU: Basis checkpoint/anchor immutability not enforced prior to approval | Sentinel Policy | Low | **[PR #8](https://github.com/solankiharsh2837/wolverine-db/pull/8)** | ✅ Resolved |

---

## Detailed Vulnerability & Resolution Log

### Issue #1: Durable Approval Nonce Replay Protection
- **Root Cause**: `validateAndPrepareRecovery` tracked consumed nonces using an ephemeral in-memory `Set<string>`, causing consumed nonces to be forgotten across process restarts while `wolverine_sys.approval_nonces` table was dead code.
- **Fix**: Implemented `IApprovalNonceStore` interface with `PostgresNonceStore` and `InMemoryNonceStore`. Added PostgreSQL SQL `23505` (unique violation) handling to guarantee durable atomic consumption.
- **Tests**: `tests/recovery/durable_nonce.test.ts` (11 tests).

### Issue #2: Ledger Record Cryptographic Binding
- **Root Cause**: `TrustGatewayServer.ingestCommitment` retrieved the tail record `records[records.length - 1]!` from `WolverineTrustLedger` without verifying that the record corresponded to the currently attested commitment.
- **Fix**: Added `processAttestationsWithRecord` to `TrustConsensusEngine` and secondary index maps (`getRecordByCommitmentId`, `getRecordByCertificateDigest`) in `WolverineTrustLedger`. Enforced cryptographic assertion at gateway ingress.
- **Tests**: `tests/runtime/gateway_binding.test.ts` (4 tests).

### Issue #3: Gateway Ingress Signer Authentication
- **Root Cause**: Ingress gateway checked tenant and database registration but delegated customer Ed25519 signature verification to downstream validators.
- **Fix**: Added `verifyCustomerCommitment(commitment, tenant.customerPubkey)` check in `TrustGatewayServer.ingestCommitment` and `TrustNetworkService.submitCommitment` before dispatching RPCs to validators.
- **Tests**: `tests/runtime/gateway_auth.test.ts` (5 tests).

### Issue #4: Sentinel Policy Gate TOCTOU Defense
- **Root Cause**: `PolicyGate.evaluateProposal` assumed checkpoint store immutability without invoking `verify()` and lacked pre-approval re-verification of the basis checkpoint digest and finalized on-chain EVM anchor.
- **Fix**: Added `await externalVaultStore.verify(sourceCheckpointId)` check and atomic pre-approval re-verification of the basis checkpoint Merkle root, digest, and finalized EVM anchor.
- **Tests**: `tests/sentinel/policy_gate.test.ts` (4 tests).
