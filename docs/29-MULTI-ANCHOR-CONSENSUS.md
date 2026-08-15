# Multi-Anchor Consensus Engine

WolverineDB v0.3 introduces multi-anchor consensus, eliminating reliance on any single blockchain or storage provider.

## Quorum Evaluation Policies

A deployment registers multiple heterogeneous anchor targets (e.g. S3 WORM, Ethereum Mainnet, Arbitrum L2) and configures a consensus threshold:

```text
2 / 3 anchors match -> CONSENSUS_VALID
1 / 3 anchors match -> CONSENSUS_SUSPICIOUS (Alert dispatched)
0 / 3 anchors match -> CONSENSUS_DIVERGENCE (Critical incident)
```

## Fault Tolerance Matrix

- **Single Chain RPC Outage**: If one blockchain RPC endpoint is temporarily offline, remaining anchors continue satisfying quorum ($2/2$ remaining valid $\ge M$).
- **Chain Reorganization**: If a transient reorg occurs on a fast rollup, confirmation depth requirements prevent premature finalization until consensus settles.
- **Provider Malice / Compromise**: If an attacker compromises a single anchor registry key, they cannot forge state without convincing $M-1$ other independent networks.
