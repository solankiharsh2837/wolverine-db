# Reconstruction CLI Reference

WolverineDB v0.6 provides a complete CLI surface for state reconstruction and certificate auditing.

## Command Reference

### `wdb frontier --database <id>`
Inspects database state, queries external anchors, and calculates the Verified State Frontier.
```bash
wdb frontier --database pg-prod-ledger-01
```

### `wdb reconstruct --database <id>`
Calculates the reconstruction manifest and previews preserved vs. excluded transactions.
```bash
wdb reconstruct --database pg-prod-ledger-01
```

### `wdb recovery-plan --database <id>`
Generates the formal `AdvisoryRecoveryProposal` and evaluates Policy Gate requirements.
```bash
wdb recovery-plan --database pg-prod-ledger-01
```

### `wdb recovery-certificate --recovery-id <id>`
Outputs the official State Recovery Certificate.
```bash
wdb recovery-certificate --recovery-id rec-20260816-000184
```

### `wdb recover --recovery-id <id> --signatures <file>`
Executes atomic recovery upon verifying multi-party Ed25519 authorization envelopes.
```bash
wdb recover --recovery-id rec-20260816-000184 --signatures approvals.json
```
