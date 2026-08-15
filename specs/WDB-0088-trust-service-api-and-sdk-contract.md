# WDB-0088: Trust Service API and SDK Contract

Status: Normative Specification (v0.8.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the API and SDK contracts between customer-side `WolverineEvidenceAgent` instances and the managed Wolverine Trust Network cloud service.

## 2. API Endpoints Contract

- `POST /v1/trust/commitments`
  - Ingests signed `TrustCommitment`.
  - Returns `CommitmentIngestionReceipt` containing `status: 'SUBMITTED' | 'QUEUED'`.
- `GET /v1/trust/commitments/:commitmentId/status`
  - Returns current state: `'SUBMITTED' | 'ATTESTED' | 'QUORUM_REACHED' | 'FINALIZED' | 'EQUIVOCATION'`.
- `GET /v1/trust/proofs/:checkpointId`
  - Returns complete, standalone `PortableTrustProof`.
- `GET /v1/trust/network/validators`
  - Returns active `ValidatorSet` (IDs and Ed25519 public keys).

## 3. Asynchronous Offline Contract

- The customer SDK **MUST NOT** block or halt database transactions when the Trust API is unreachable.
- Offline commitments MUST be stored in local durable storage and submitted in strictly increasing `commitSeq` order upon network restoration.
