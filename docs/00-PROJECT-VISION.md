# Project vision

WolverineDB provides immutable change history, cryptographic state verification, authorization provenance, tamper detection, and selective recovery over existing databases.

## Goals

Preserve an auditable account of change; make independently reproducible integrity claims; localize divergence; and recover only approved affected fields or records while retaining the forensic trail.

## Non-goals

It is not a replacement for PostgreSQL, a blockchain database, a generic backup system, or an autonomous database administrator. It does not infer intent from a hash mismatch and must never make destructive recovery decisions without policy and required approval.

## Principles

Append-only history, deterministic encoding, explicit trust boundaries, least authority, evidence preservation, and honest failure reporting govern all releases.
