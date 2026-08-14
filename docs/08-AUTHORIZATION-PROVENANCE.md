# Authorization and provenance

Every protected change carries or references an immutable authorization envelope: actor, authenticated identity, session, request, service, transaction, source, timestamp, policy decision, approval/change ticket, and stated reason where available.

Verification classification is `AUTHORIZED`, `UNKNOWN`, `SUSPICIOUS`, or `UNAUTHORIZED`. The classification records available evidence and policy evaluation; a cryptographic mismatch alone does not establish malicious intent. A missing envelope is not silently treated as authorized.

**UNRESOLVED:** identity attestation and external ticket-provider integration are adapter policies, not protocol defaults.
