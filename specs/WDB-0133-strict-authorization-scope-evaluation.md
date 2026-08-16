# WDB-0133: Strict Authorization Scope Evaluation

**Status**: Normative (Frozen)  
**Version**: 1.3.0  
**Domain**: Sentinel Policy Gate & Autonomous Recovery Safety

---

## 1. Abstract

This specification eliminates prefix, suffix, and substring scope leakage during recovery proposal evaluation and execution.

---

## 2. Formal Scope Resolution Model

A table identifier $\text{Table}$ matches a protected scope $\text{Scope}$ if and only if:

1. **Exact Table Match**: $\text{Scope} = \text{Table}$ (e.g. `public.users` matches `public.users`).
2. **Schema-Level Wildcard Match**: $\text{Scope} = \text{Schema}.\ast$ and $\text{Table} = \text{Schema}.\text{TableName}$ (strictly separated by delimiter `.`).
3. **Global Wildcard Match**: $\text{Scope} \in \{ \ast, \text{"global"} \}$.

### Forbidden Evaluation Patterns
- Substring checking (`record.tableName.includes(...)`) is strictly prohibited.
- Unbounded prefix checking (`record.tableName.startsWith(...)` without schema delimiter) is strictly prohibited.
- `public.users_backup`, `public.users_archive`, and `private.users` MUST NOT match `public.users`.
