# Standalone Daemons & CLI Reference

Wolverine provides standalone CLI daemons for running the distributed trust cluster:

```bash
# Launch a validator daemon
wdb-validator --id val-01 --listen 127.0.0.1:9001 --data ./data/val-01 --epoch 1

# Launch the Trust Gateway
wdb-gateway --listen 127.0.0.1:8080 --validators 127.0.0.1:9001,127.0.0.1:9002...

# Launch a persistent ledger replica
wdb-replica --id rep-01 --listen 127.0.0.1:9101 --data ./data/rep-01

# Run customer agent
wdb-agent --connect postgres://postgres@localhost:5432/orders --gateway http://127.0.0.1:8080

# Verify an exported receipt offline
wdb receipt verify ./receipt-1842.json
```
