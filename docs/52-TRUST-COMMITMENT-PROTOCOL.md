# Trust Commitment Protocol & Tenant Isolation

A `TrustCommitment` encapsulates a cryptographic promise from a customer's database node to the Trust Network.

## Domain Separation
Every commitment digest is calculated as:
$$\text{CommitmentDigest} = \text{SHA-256}(\text{"WDB:TRUST:v1:"} \parallel \text{RFC8785\_Canonicalize}(\text{payload}))$$

This guarantees that:
1. No commitment from Tenant $A$ can be replayed or ingested under Tenant $B$.
2. Sequence numbers within a database namespace remain strictly ordered and hash-linked.
3. Customer private keys authenticate all outward commitments.
