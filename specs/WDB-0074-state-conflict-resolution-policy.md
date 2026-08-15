# WDB-0074: State Conflict Resolution Policy

Status: Normative Specification (v0.7.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification formalizes the conflict detection and fail-closed handling rules when reconstructing state across divergent branches, split checkpoints, or competing mutations.

## 2. Conflict Invariant: Never Guess

When two independently provable mutations conflict (for example, two valid branches concurrently updating the same row $pk$ without linear ordering):
1. The reconstruction engine **MUST NOT** guess or apply arbitrary heuristics (e.g., "last write wins" or "lowest ID").
2. The conflicting mutations MUST be flagged with status `STATE_CONFLICT`.
3. The reconstruction engine MUST generate a `ConflictResolutionRequest` requiring explicit multi-party Ed25519 authorization.
4. If no explicit resolution is provided, the engine **FAILS CLOSED** and refuses to materialize state for that row version.
