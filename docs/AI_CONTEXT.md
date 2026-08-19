# WolverineDB // AI Agent Context & Engineering Directives

> **Source Code is Authoritative.**  
> This guide provides autonomous AI coding agents with strict directives, architectural constraints, test commands, and anti-patterns for working within the **WolverineDB** codebase.

---

## 1. Project Nature & Core Identity

- **What WolverineDB IS**: An independent, cryptographic trust, state reconstruction, and Byzantine consensus engine for databases (PostgreSQL/SQLite/MySQL).
- **What WolverineDB is NOT**: It is NOT a web application, website, frontend framework, React app, or database replacement engine. Do not add React, Next.js, HTML, CSS, or browser-specific libraries.

---

## 2. Mandatory Workflow Before Modifying Code

```
┌────────────────────────────────────────────────────────┐
│ 1. Read the relevant spec in docs/ (e.g., BYZANTINE_CONSENSUS.md)
│ 2. Find existing cryptographic primitives in src/crypto/ or src/binary/
│ 3. Check invariants (c14n canonicalization, domain prefixes, durable nonces)
│ 4. Implement smallest coherent change preserving backward compatibility
│ 5. Compile: npm run build
│ 6. Verify: npm test
└────────────────────────────────────────────────────────┘
```

---

## 3. Strict Rules & Anti-Patterns for AI Agents

1. **NEVER Skip Canonical JSON (`c14n`)**:
   - Never use `JSON.stringify` directly when computing SHA-256 digests or cryptographic signatures. Always use `canonicalizeJson` from [`src/binary/c14n.ts`](../src/binary/c14n.ts).
2. **NEVER Use In-Memory State for Durable Guarantees**:
   - Replay protection, consumed nonces, and finalized sequence numbers must be stored durably via `IApprovalNonceStore` or `WolverineTrustLedger`.
3. **NEVER Bypass Gateway Ingress Authentication**:
   - Ingress gateways must verify customer Ed25519 signatures via `verifyCustomerCommitment` before forwarding RPC requests to validators.
4. **Preserve Domain Separation**:
   - Always prepend standard UTF-8 domain prefixes (`WDB:COMMITMENT:v1:`, `WDB:TRUST:v1:`, etc.) before SHA-256 hashing.
5. **Always Use Timing-Safe Comparison**:
   - Always use `timingSafeEqualHashes` from [`src/crypto/hash.ts`](../src/crypto/hash.ts) when comparing hashes, digests, or public keys.

---

## 4. Standard Commands

- **Build**: `npm run build` (compiles TypeScript via `tsc` to `dist/`)
- **Test Full Suite**: `npm test` (runs all 91 Vitest test suites)
- **Single Test**: `npx vitest run tests/sentinel/policy_gate.test.ts`
