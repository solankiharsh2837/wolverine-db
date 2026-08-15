# WDB-0125: Byzantine State Proof and Malicious Snapshot Defense Protocol

Status: Normative Specification (v1.2.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details defense mechanisms against malicious snapshots or dishonest peer state claims.

## 2. Validator State Proof Invariant

A validator cannot assert a state by simple proclamation. Every state claim MUST provide a `ValidatorStateProof` containing:
- `ledgerSeq`
- `ledgerStateRoot`
- `journalHeadDigest`
- `epoch`
- `validatorSetDigest`
- Supporting quorum certificates and receipts.

## 3. Cryptographic Decision Rule

When comparing multiple state claims:
- The node MUST NOT select a state simply because a numerical majority claims it.
- The node MUST select ONLY the state supported by valid cryptographic finality certificates and unbroken hash chain provenance.
- If a forged snapshot is detected (e.g. from compromised cloud storage), the engine rejects the snapshot and recovers from the latest independently proven state.
