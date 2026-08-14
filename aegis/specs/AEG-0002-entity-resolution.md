# AEG-0002: Entity Extraction & Resolution Rules

Status: Normative Specification (v0.1 Frozen).

## Entity Types

AEGIS extracts 6 core entity types:
- `HANDLE`: Usernames, handles, PGP key IDs.
- `INFRASTRUCTURE`: IPv4/IPv6, domains, ASN, SSL certificate hashes.
- `ARTIFACT`: File SHA-256 hashes, YARA rule matches, binary signatures.
- `FINANCIAL`: Bitcoin / Ethereum / Monero wallet addresses.
- `LOCATION`: Geolocation / timezone metadata.
- `STYLOMETRY`: Language patterns, writing style markers.

## Resolution Rules

When two entity nodes share high confidence attributes (e.g. matching PGP key ID or identical BTC wallet address), entity resolution merges them into an `ActorCandidateProfile`:

```typescript
interface ActorCandidateProfile {
  actorId: string;
  primaryHandle: string;
  aliases: string[];
  entityNodeIds: string[];
  confidenceScore: number; // 0 to 100
}
```
