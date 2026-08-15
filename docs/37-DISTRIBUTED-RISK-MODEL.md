# Explainable Distributed Risk Model

WolverineDB v0.5 rejects black-box machine learning probability scores in favor of a deterministic, explainable linear risk formulation.

## Mathematical Formulation

$$R = \min\left(100, \sum_{i=1}^{5} w_i \cdot S_i\right)$$

Where:
- $S_{\text{state}}$ ($w = 0.35$): Direct cryptographic evidence of database tampering.
- $S_{\text{prov}}$ ($w = 0.20$): Missing ticket IDs, session hijacking, or untrusted execution routes.
- $S_{\text{beh}}$ ($w = 0.20$): Out-of-window mutations, velocity spikes, or unauthorized scope expansions.
- $S_{\text{hist}}$ ($w = 0.10$): Historical incident count for the actor identity.
- $S_{\text{ext}}$ ($w = 0.15$): Threat intelligence indicators from AEGIS.

Every incident provides an itemized score breakdown detailing the exact numerical contribution and raw cryptographic evidence associated with each signal.
