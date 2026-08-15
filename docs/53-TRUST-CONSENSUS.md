# Trust Consensus & Quorum Finality

The Wolverine Trust Network employs a dedicated $M$-of-$N$ threshold attestation consensus mechanism.

## Consensus Flow
1. **Ingestion**: The Trust API receives and timestamps a `TrustCommitment`.
2. **Attestation**: Registered validator nodes inspect the commitment, verify the customer signature and hash-chain sequence, and emit signed `ValidatorAttestation` records.
3. **Quorum Assembly**: The consensus engine aggregates attestations. Once $M$ valid signatures are collected, a `QuorumCertificate` is issued.
4. **Ledger Finalization**: A `FINALIZATION` record is appended to the Trust Ledger, permanently anchoring the state.
