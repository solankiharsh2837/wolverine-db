# WDB-0091: Trust Gateway and Transport Protocol

Status: Normative Specification (v0.9.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification defines the HTTP/REST transport protocol, JSON-RPC communication grammar, and gateway dispatch contracts between customer agents, gateway routers, and validator nodes.

## 2. Gateway Endpoints

- `POST /v1/commitments`: Ingests `TrustCommitment`. Returns `202 Accepted` (with receipt) or `200 OK` (with finalized `PortableTrustProof` when synchronous).
- `GET /v1/proofs/:checkpointId`: Returns `PortableTrustProof` for a finalized checkpoint.
- `GET /v1/validators`: Returns active validator public keys.
- `GET /v1/health`: Returns node cluster health and consensus quorum status.

## 3. Network Transport Message Framing

All requests and responses use RFC 8785 canonical JSON framing with UTF-8 encoding and Content-Type `application/json; charset=utf-8`.
BigInt sequence numbers MUST be serialized as decimal string primitives in JSON representations.
