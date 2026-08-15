# WDB-0114: Immutable Trust Receipt Format Protocol

Status: Normative Specification (v1.1.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Product Primitive

This specification defines the **Immutable Trust Receipt** — the core commercial product artifact delivered to customers upon checkpoint finalization.

## 2. Receipt Schema (`application/vnd.wolverine.trust-receipt+json`)

```json
{
  "receiptVersion": 1,
  "receiptId": "rcpt-550e8400-e29b-41d4-a716-446655440000",
  "tenantId": "enterprise-alpha",
  "databaseId": "production-orders",
  "databaseTime": {
    "checkpointId": "00000000-0000-0000-0000-000000001842",
    "commitSeq": "1842",
    "checkpointDigestHex": "69f91f489e3edd5d..."
  },
  "trustTime": {
    "ledgerSeq": "8271",
    "epoch": 7,
    "finalizedAtUs": "1786831241008000",
    "merkleStateRootHex": "a1b2c3d4..."
  },
  "consensus": {
    "validatorSetId": "valset-prod-v1",
    "quorumCount": 5,
    "totalValidators": 5,
    "quorumCertificateDigestHex": "f97de64d..."
  },
  "portableProof": { ... },
  "receiptDigestHex": "3f4b5c..."
}
```

## 3. Product Guarantee

> **“Your database can lie. Your audit trail cannot.”**
> Any third-party auditor possessing an `ImmutableTrustReceipt` can run `wdb receipt verify <receipt.json>` offline to verify mathematical and historical authenticity.
