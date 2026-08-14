# Security model

Trust boundaries are Application, Wolverine components, PostgreSQL, immutable external checkpoint storage, and optional anchor network. Credentials are least-privilege and separated: writers cannot rewrite history; verifiers need read access; recovery approvers are distinct from recovery executors where feasible.

A compromised PostgreSQL host can alter live state and local metadata. External immutable checkpoints and independently held verification material limit undetected retrospective rewrite, but cannot prevent forward fabrication by an attacker with all relevant credentials. Deployments need backups, monitoring, key rotation, access control, and incident response in addition to WolverineDB.
