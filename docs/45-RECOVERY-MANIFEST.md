# Reconstruction Manifest & Proof Auditing

The Reconstruction Manifest provides an irrefutable cryptographic record of state recovery.

## Manifest Structure

```json
{
  "manifestVersion": 1,
  "manifestId": "3b2e5a71-8c4d-4e9f-9a1b-0c2d3e4f5a6b",
  "databaseId": "pg-prod-ledger-01",
  "tenantId": "org-enterprise-finance",
  "sourceCheckpointId": "chk-00000000-0000-0000-0000-000000001842",
  "sourceCheckpointCommitSeq": "42",
  "startingMerkleRoot": "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b",
  "endingCommitSeq": "46",
  "replayedChangeIds": ["chg-43", "chg-44", "chg-45", "chg-46"],
  "replayedCommitSeqs": ["43", "44", "45", "46"],
  "excludedChangeIds": ["chg-47", "chg-48", "chg-49", "chg-50"],
  "exclusionReasons": {
    "chg-47": "UNAUTHORIZED_SCOPE_MUTATION (Actor dba_compromised modified public.users outside window)",
    "chg-48": "POST_COMPROMISE_MUTATION",
    "chg-49": "POST_COMPROMISE_MUTATION",
    "chg-50": "HISTORY_HASH_CHAIN_TAMPERED"
  },
  "reconstructedMerkleRoot": "7f6e5d4c3b2a109876543210fedcba9876543210abcdef0123456789abcdef01",
  "recoveryBoundary": {
    "lastValidCommitSeq": "46",
    "lastValidTimestampUs": "1723503900000000",
    "firstInvalidCommitSeq": "47",
    "compromiseReason": "Out-of-window unauthorized mutation with corrupted hash chain"
  }
}
```

The manifest is cryptographically hashed (`reconstructionDigest`) and permanently stored in `wolverine_sys.reconstruction_manifests`.
