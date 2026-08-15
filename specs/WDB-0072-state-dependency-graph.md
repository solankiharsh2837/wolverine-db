# WDB-0072: State Dependency Graph Protocol

Status: Normative Specification (v0.7.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the **State Dependency Graph** (`StateDependencyGraph`). Because database operations are state-dependent, a mutation cannot be replayed merely because it is cryptographically authentic—it must also be causally sound and independent of excluded malicious or corrupted mutations.

## 2. Dependency Tracking Model

For every change record $R$, dependencies are extracted across three dimensions:

1. **Row Version Predecessor Dependency**:
   If $R$ is an `UPDATE` or `DELETE`, $R$ depends on the exact prior version of the target row ($pk$) produced by a specific preceding commit sequence ($S_{\text{dep}}$).
2. **Key Existence Dependency**:
   If $R$ is an `INSERT`, $R$ asserts that the primary key does not exist prior to $R$.
3. **Foreign Key Reference Dependency**:
   If $R$ references a foreign key tuple in another table, $R$ depends on the existence of that foreign row in the reconstructed state.

## 3. Dependency Safety Rule

- If a mutation $R$ depends on sequence $S_{\text{dep}}$, and $S_{\text{dep}}$ was classified as `EXCLUDED`, `INVALID`, or `COMPROMISED`:
  - $R$ **MUST NOT** be replayed.
  - $R$ **MUST** be classified as `DEPENDENCY_BLOCKED`.
  - The dependency failure reason MUST be recorded: `DEPENDS_ON_EXCLUDED_MUTATION(seq=S_dep)`.

## 4. Deterministic Dependency Digest

$$\text{DependencyGraphDigest} = \text{SHA-256}(\text{"WDB:DEP\_GRAPH:v1:"} \parallel \text{RFC8785\_Canonicalize}(\text{dependencies}))$$
