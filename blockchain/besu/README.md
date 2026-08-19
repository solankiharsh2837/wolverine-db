# Hyperledger Besu Wolverine Trust Chain Subsystem

## Overview
This directory contains the production-grade private permissioned blockchain infrastructure for WolverineDB using Hyperledger Besu with QBFT (Quorum Byzantine Fault Tolerance) consensus.

## Network Parameters
- **Chain ID**: `13370` (`wolverine-trust-chain`)
- **Consensus**: `QBFT`
- **Block Time**: `1 second`
- **Validators**: 5 dedicated containerized nodes
- **Fault Tolerance**: Tolerates $F=1$ Byzantine validator node failure in a 5-node cluster.

## Architecture
```
Wolverine Gateway
      │ (JSON-RPC)
      ▼
besu-validator-1 (0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf)
      │
      ├──── QBFT P2P ──── besu-validator-2
      ├──── QBFT P2P ──── besu-validator-3
      ├──── QBFT P2P ──── besu-validator-4
      └──── QBFT P2P ──── besu-validator-5
```

## Quick Start
```bash
# Start 5 Besu validators and PostgreSQL
docker compose -f blockchain/besu/docker-compose.yml up -d

# Check cluster logs
docker logs -f besu-validator-1
```
