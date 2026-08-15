# WDB-0103: Compromised Gateway and Equivocation Defense Protocol

Status: Normative Specification (v1.0.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Threat Model: Compromised Wolverine Control Plane & Gateway

Assume the adversary has full root access to the Wolverine Cloud Gateway, API servers, and routing infrastructure.

The adversary attempts:
1. **Conflicting State Forgery**: Submit altered checkpoint digest $D_B$ for previously finalized commitSeq $S$.
2. **Signature Forgery**: Generate fake validator attestations without private keys.
3. **Replay Attack**: Inject historical commitments from past epochs.
4. **Mutilated Quorum**: Present an incomplete or manipulated quorum certificate.

## 2. Validator Defensive Invariants

- Every validator daemon evaluates commitments against its own independent persistent journal.
- If a commitment presents a conflicting digest for an already-attested sequence ($S_{\text{new}} \le S_{\text{last}}$ with $D_{\text{new}} \ne D_{\text{last}}$), the validator **MUST** reject with `EQUIVOCATION_DETECTED` and generate signed slashable evidence.
- The consensus engine requires $\ge M$ valid cryptographic signatures from distinct registered validator public keys; fabricated or duplicate validator signatures are discarded.
- When $< M$ valid attestations exist, the network **FAILS CLOSED** with `CONSENSUS_UNAVAILABLE`.
