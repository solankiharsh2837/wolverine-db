# Versioning

Every committed protected transaction produces an immutable version with an identifier, parent version, transaction reference, state root, and status. v0.1 is a linear parent chain: no history rewriting, deletion, or user-visible branching.

A recovery never edits an old version. It creates a later `RECOVERY` version referencing the incident and trusted basis. Versions may be marked `TRUSTED`, `SUSPECT`, `COMPROMISED`, or `RECOVERED` by recorded assessment; a status is not a deletion.

Branch support is **UNRESOLVED** and out of scope for v0.1.
