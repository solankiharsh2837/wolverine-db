# WDB-0092: Independent Validator Daemon Protocol

Status: Normative Specification (v0.9.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the standalone validator daemon (`TrustValidatorDaemon`).

## 2. Validator Daemon Lifecycle

1. **Bootstrapping**: Loads node private key from encrypted storage or HSM; publishes Ed25519 public key to validator registry.
2. **Attestation Server**: Binds to a dedicated network socket listening for `ATTEST_REQUEST` RPC messages.
3. **Verification Engine**: Executes deterministic WDB-0083 checks on incoming commitments.
4. **Signature Emission**: Returns signed `ValidatorAttestation` over network socket to the consensus coordinator.

## 3. Network RPC Interface

- `POST /rpc/attest`: Body: `{ commitment: TrustCommitment, tenantPubkeyHex: string }`
  - Response `200 OK`: `{ attestation: ValidatorAttestation }`
  - Response `400 Bad Request`: `{ error: string, code: WolverineErrorCode }`
