# WDB protocol concepts

Database: protected PostgreSQL scope. Transaction: an atomic committed database operation. Change: one observed row mutation. ChangeRecord: canonical, signed-or-linked evidence of that change. Version: immutable logical state transition. Checkpoint: commitment to a defined set of versions. StateRoot: ordered commitment to protected state. MerkleRoot: tree root for checkpoint leaves. Anchor: external publication of a checkpoint commitment. Incident: recorded verification or policy concern. Recovery: an approval-governed corrective transaction that produces a new version.

Relationships are one-to-many from transaction to changes and many-to-one from changes to version/checkpoint. The normative record grammar is `specs/WDB-0001-protocol.md` and binary form is `specs/WDB-0002-binary-format.md`.
