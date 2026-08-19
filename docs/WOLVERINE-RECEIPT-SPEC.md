# Wolverine Universal Trust Receipt Specification (v2.0)

**Document Status**: Normative Specification (v2.0 Frozen)  
**Schema**: JSON / RFC 8785 Canonical Encoding

---

## 1. Scope & Objective

The **Universal Trust Receipt** is the authoritative, self-contained, portable cryptographic proof produced by WolverineDB upon block finalization on the Hyperledger Besu Trust Chain.

It binds the customer database evidence plane directly to the permissioned blockchain ledger, enabling instant zero-trust verification on air-gapped auditor machines.

---

## 2. Canonical JSON Schema

```json
{
  "receiptVersion": 2,
  "receiptId": "ca068b9d-b328-4adb-b0e9-a14e8463639d",
  "tenantId": "tenant_acme_corp",
  "databaseId": "prod_db_postgres",
  "timestampUs": "1724122800000000",
  "evidencePlane": {
    "checkpointId": "00000000-0000-0000-0000-000000000001",
    "commitSeq": "1",
    "lsn": "0/16FF000",
    "checkpointDigestHex": "c45863757d14f46dff14bd7202ec343dee96e02436617348c949e4a87b24b5e3",
    "stateMerkleRootHex": "24258a0d646ed10e4fe99a3cf34ae2fba616afd3b8009605cd5f49f0530af603",
    "changeChainHeadHex": "a1b2c3d4e5f6...",
    "agentAttestationHex": "e4f5...",
    "customerAuthorizationHex": "d1e2..."
  },
  "trustPlane": {
    "networkId": "wolverine-besu-cluster",
    "chainId": 13370,
    "blockchainTransactionHash": "0x8b3f5c9e2d1a4b7e8c3f5c9e2d1a4b7e8c3f5c9e2d1a4b7e8c3f5c9e2d1a4b7e",
    "blockNumber": "4281",
    "blockHash": "0x99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff",
    "finalityStatus": "FINALIZED",
    "contractAddress": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    "previousCommitmentDigestHex": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "optionalPublicAnchor": {
    "status": "NONE"
  },
  "receiptDigestHex": "74e22f19e2e276707bc693272deff7de01f2fd0f0002c7f133a7040c359a5adc"
}
```

---

## 3. Cryptographic Verification Rules

1. **Receipt Digest Invariance**:
   $$\text{receiptDigest} = \text{SHA-256}(\text{"WDB:UNIVERSAL\_RECEIPT:v2:"} \parallel \text{CanonicalJSON}(\text{receipt}))$$
2. **Customer Authorization**:
   $$\sigma_{\text{cust}} = \text{Ed25519\_Verify}(K_{\text{cust}}, \text{"WDB:CUST\_AUTH:v2:"} \parallel D_{\text{commit}} \parallel \text{commitSeq})$$
3. **Agent Attestation**:
   $$\sigma_{\text{agent}} = \text{Ed25519\_Verify}(K_{\text{agent}}, \text{"WDB:AGENT\_ATTEST:v2:"} \parallel D_{\text{commit}} \parallel \text{lsn})$$
4. **State Merkle Root Verification**:
   When given a snapshot of the database at sequence $N$, compute the RFC 6962 Merkle tree root $R_{\text{eval}}$ over canonical table rows. If $R_{\text{eval}} \ne R_{\text{receipt}}$, emit `LOCAL_TAMPERING_DETECTED`.
