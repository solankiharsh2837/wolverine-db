# WDB-0021: EVM Anchor Adapter

Status: Normative Specification (v0.3 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the EVM smart contract interface, transaction construction, confirmation depth rules, gas pricing constraints, and RPC failure handling for anchoring WolverineDB checkpoints to EVM-compatible blockchains (e.g. Ethereum, Arbitrum, Base, Optimism, Polygon).

## 2. Smart Contract Reference Interface

The canonical EVM anchor registry contract exposes the following interface:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IWolverineAnchorRegistry {
    event CheckpointAnchored(
        bytes16 indexed checkpointId,
        bytes32 indexed checkpointDigest,
        uint64 commitSeq,
        uint64 timestampUs,
        address indexed publisher
    );

    function anchorCheckpoint(
        bytes16 checkpointId,
        bytes32 checkpointDigest,
        uint64 commitSeq,
        uint64 timestampUs
    ) external returns (bool);

    function getAnchor(bytes16 checkpointId)
        external
        view
        returns (
            bytes32 checkpointDigest,
            uint64 commitSeq,
            uint64 timestampUs,
            uint64 blockNumber,
            address publisher
        );
}
```

## 3. Transaction Construction & Chain Binding

1. **Chain-ID Binding**: The adapter MUST bind each transaction to the explicitly configured `chainId` (EIP-155 replay protection).
2. **Deterministic Calldata**: Calldata is constructed using standard ABI encoding of function selector `0x3a920f6b` (`anchorCheckpoint(bytes16,bytes32,uint64,uint64)`).
3. **Idempotency & Conflict**: If a checkpoint ID is already recorded on-chain:
   - If the recorded digest matches the current digest, the anchor is considered successfully fulfilled (`IDEMPOTENT_OK`).
   - If the recorded digest differs from the current digest, the adapter MUST throw a `ConflictingAnchorCommitmentError`.

## 4. Confirmation Depth & Reorg Mitigation

To protect against chain reorganizations, an anchor MUST NOT transition to `FINALIZED` status until it has accumulated the chain's required confirmation blocks:
- **Ethereum Mainnet (PoS)**: 64 blocks (~12.8 minutes / 2 epochs for finality).
- **Arbitrum / Optimism / Base (Rollups)**: 120 blocks or L1 state batch finalization.
- **Polygon PoS**: 128 blocks.
- **Local Dev / Testnet**: 1 block.

## 5. Gas Limits & RPC Outage Resilience

1. **Max Gas Price**: The adapter MUST refuse to broadcast transactions if current network gas price exceeds `max_gas_price_gwei`.
2. **Fail-Closed Buffering**: In the event of RPC unavailability or network congestion, the anchor is retained in local pending queue; the core database continues processing, but `wdb verify` will report the anchor as `PENDING_CONFIRMATION`.
