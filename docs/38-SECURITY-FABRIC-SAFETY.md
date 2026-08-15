# Security Fabric Safety & Plane Isolation

This document outlines the safety architecture isolating the recovery execution plane from the application and intelligence planes.

## Attack Surface Mitigation

1. **Compromised Web Application**: If an attacker gains full code execution inside the web application, they can emit fake runtime alerts, but they **cannot** invoke recovery commands directly or forge Ed25519 signatures.
2. **Adversarial / Corrupted Intelligence (AEGIS)**: If AEGIS threat feeds are manipulated, Sentinel can at most formulate an advisory proposal. The Deterministic Policy Gate will reject any proposal that does not match an authentic, externally anchored checkpoint.
3. **Privilege Separation**: The entity requesting recovery cannot sign the approval envelope, preventing unilateral restoration of compromised states.
