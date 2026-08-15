# WDB-0124: Epoch Transition Certificate and Handoff Protocol

Status: Normative Specification (v1.2.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the cryptographic structure and validation rules for `EpochTransitionCertificate`.

## 2. Certificate Schema

$$\begin{aligned}
\text{EpochTransitionCertificate} = \{ & \text{oldEpoch}, \text{newEpoch}, \\
& \text{oldValidatorSetDigest}, \text{newValidatorSetDigest}, \\
& \text{transitionLedgerSeq}, \text{transitionReason}, \\
& \text{oldQuorumAuthorization}, \text{newQuorumAuthorization} \}
\end{aligned}$$

## 3. Strict Transition Rules

- A decommissioned validator signing after its epoch transition MUST be rejected.
- A new validator signing sequences prior to its activation MUST be rejected.
- Two competing epoch transitions for the same epoch MUST trigger `FAIL_CLOSED_COMPETING_EPOCHS`.
