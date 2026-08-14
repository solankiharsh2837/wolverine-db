# Testing and validation

Required suites cover authorized inserts/updates/deletes, DBA changes, unknown and unauthorized provenance, hash and history tampering, missing events, Merkle/checkpoint/anchor verification, single-field and multi-record recovery, concurrent transactions, rollbacks, and crashes during commit/checkpoint.

Attack simulations directly change a protected row, mutate/delete a history event, alter a checkpoint, replay a change, and alter authorization metadata. Each must prove detection or explicitly demonstrate its documented limitation. Deterministic fixtures belong in `specs/TEST-VECTORS.md`.
