# WolverineDB // CLI & Daemon Specifications

> **Source Code is Authoritative.**  
> This specification documents the `wdb` command-line binary, background daemon processes, runtime flags, and configuration interfaces of **WolverineDB v1.3.0**.

---

## 1. CLI Binary Overview (`wdb`)

The command-line interface is built using **Commander.js** and exposed as `wdb` via `dist/cli/index.js` ([`src/cli/index.ts`](../src/cli/index.ts)).

```bash
wdb [command] [options]
```

### Core CLI Command Groups:

| Command Group | Implementation File | Purpose |
| :--- | :--- | :--- |
| `wdb start <daemon>` | [`src/daemons/cli_binaries.ts`](../src/daemons/cli_binaries.ts) | Starts background daemon processes (`gateway`, `validator`, `replica`, `agent`). |
| `wdb cluster <action>` | [`src/runtime/cli.ts`](../src/runtime/cli.ts) | Initializes, starts, or checks status of distributed trust clusters. |
| `wdb reconstruct <args>` | [`src/reconstruction/cli.ts`](../src/reconstruction/cli.ts) | Executes verified state reconstruction and transaction replay. |
| `wdb verify <proof>` | [`src/trust_network/cli.ts`](../src/trust_network/cli.ts) | Validates portable trust proofs offline against validator public keys. |
| `wdb survivability <cmd>` | [`src/survivability/cli_survivability.ts`](../src/survivability/cli_survivability.ts) | Manages disaster recovery queues, journals, and SLA status. |

---

## 2. Background Daemon Processes (`src/daemons/`)

### 1. Gateway Daemon (`src/daemons/gateway_daemon.ts`)
- **Role**: Ingress boundary server receiving customer commitments, verifying Ed25519 signatures, dispatching to validators, and issuing finalized trust proofs.
- **Flags**:
  - `--port <number>`: Ingress HTTP/RPC port (default: `8080`).
  - `--host <string>`: Bind address (default: `0.0.0.0`).
  - `--quorum <number>`: Minimum required validator quorum (default: `3`).
  - `--validators <list>`: Comma-separated validator endpoint URLs.

### 2. Validator Daemon (`src/daemons/validator_daemon.ts`)
- **Role**: Independent validator node validating commit sequences, verifying customer keys, and signing BFT attestations.
- **Flags**:
  - `--id <validatorId>`: Unique validator identifier (e.g., `val-01`).
  - `--key <path>`: Path to Ed25519 validator private key.
  - `--port <number>`: Attestation RPC listen port (default: `9001`).

### 3. Replica Daemon (`src/daemons/replica_daemon.ts`)
- **Role**: Read-only ledger replica syncing finalized records from master gateway nodes.

### 4. Agent Daemon (`src/daemons/agent_daemon.ts`)
- **Role**: Database agent tailing PostgreSQL logical replication slots and submitting commitments to the Trust Gateway.
