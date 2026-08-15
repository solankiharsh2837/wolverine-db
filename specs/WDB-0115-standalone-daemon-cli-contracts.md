# WDB-0115: Standalone Daemon CLI Contracts Protocol

Status: Normative Specification (v1.1.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Daemon CLI Specifications

- `wdb-validator`: Runs an independent validator daemon.
  - `--id <id>`: Validator identifier (e.g. `val-01`).
  - `--listen <host:port>`: RPC bind socket.
  - `--data <dir>`: Persistent local sequence journal.
  - `--epoch <num>`: Active network epoch.

- `wdb-gateway`: Runs the Trust Gateway router.
  - `--listen <host:port>`: HTTP bind socket.
  - `--validators <endpoints>`: Validator cluster endpoints.
  - `--replicas <endpoints>`: Ledger replica endpoints.

- `wdb-replica`: Runs a persistent ledger replica node.
  - `--id <id>`: Replica identifier.
  - `--listen <host:port>`: Replication sync socket.
  - `--data <dir>`: Persistent storage directory.

- `wdb-agent`: Customer agent daemon.
  - `--connect <dsn>`: PostgreSQL connection string.
  - `--gateway <url>`: Trust Gateway URL.
  - `--key <keyfile>`: Customer Ed25519 private key.

- `wdb receipt verify <receipt.json>`: Standalone offline trust receipt verification command.
