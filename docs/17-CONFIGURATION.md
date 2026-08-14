# Configuration

Configuration file format (YAML/JSON):

```yaml
database:
  adapter: postgres
  connection_string: "postgresql://postgres:postgres@localhost:5432/wolverinedb_test"
  protected_tables:
    - "public.users"
    - "public.accounts"

integrity:
  hashing: sha256
  merkle: true

checkpoint:
  interval: 5m

authorization:
  trusted_approvers:
    - "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" # 32-byte Ed25519 hex public key

recovery:
  mode: approval
```

Secrets (such as database credentials or private keys) MUST NOT be committed to version control and should be referenced via environment variables (`PGPASSWORD`, `WDB_APPROVER_KEY`).
