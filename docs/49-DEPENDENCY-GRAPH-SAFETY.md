# State Dependency Graph & Mutation Safety

Database operations are state-dependent. If a mutation depends on a row version created or altered by an excluded transaction, replaying it would cause semantic state corruption.

## Dependency Resolution Ladder

```text
       Mutation M_k
            │
            ▼
┌───────────────────────────┐
│ Is M_k cryptographically  │─── NO ───> EXCLUDE / INVALID
│ authentic and authorized? │
└───────────┬───────────────┘
            │ YES
            ▼
┌───────────────────────────┐
│ Does M_k depend on any    │─── YES ──> BLOCK (DEPENDENCY_BLOCKED)
│ EXCLUDED mutation?        │
└───────────┬───────────────┘
            │ NO
            ▼
┌───────────────────────────┐
│ Does M_k conflict with a  │─── YES ──> CONFLICT (STATE_CONFLICT)
│ competing valid branch?   │
└───────────┬───────────────┘
            │ NO
            ▼
       SAFE_TO_REPLAY
```
