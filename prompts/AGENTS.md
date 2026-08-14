# Instructions for coding agents

Treat `specs/WDB-0001` through `WDB-0006`, `specs/TEST-VECTORS.md`, and `docs/03` through `docs/13` as the security and protocol source of truth. Read them before modifying architecture, storage, cryptography, authorization, integrity, or recovery.

Never invent an unspecified protocol detail, silently change a cryptographic format, rewrite/delete historical versions, overwrite forensic history during recovery, or let an AI feature bypass policy or approval. Mark unresolved choices explicitly and stop for a specification decision when a choice affects bytes, hashes, trust boundaries, compatibility, or authority.

Every public API and every negative security path needs tests. Preserve transaction semantics: no history for rollbacks and no recovery execution without policy-valid authority.
