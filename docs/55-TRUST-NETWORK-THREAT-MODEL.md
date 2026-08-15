# Wolverine Trust Network Threat Model (v0.8.0)

This document analyzes security assumptions and defenses when the host infrastructure, cloud API, or validator nodes are actively hostile.

## Threat Vectors & Mitigations

| Threat | Adversarial Action | WTN Mitigation |
| :--- | :--- | :--- |
| **API Compromise** | Rogue API worker attempts to forge a finalized commitment. | Impossible without obtaining customer private key and $M$ validator private keys. |
| **Validator Collusion** | Rogue validators attempt equivocation (attesting two different digests for same sequence). | `EQUIVOCATION_DETECTED` event is triggered, aborting consensus and alerting auditors. |
| **Cross-Tenant Replay** | Attacker takes Tenant A's commitment and submits it under Tenant B. | Domain separation (`WDB:TRUST:v1:`) causes signature verification to fail. |
| **Cloud Outage** | Trust API becomes completely unreachable. | Customer Agent queues commitments locally; database operation continues uninterrupted. |
| **Ledger Tampering** | Cloud operator attempts to rewrite historical ledger record. | Hash chain breaks; offline proof verification fails. |
