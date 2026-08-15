# WDB-0043: Distributed Risk Engine & Explainable Scoring

Status: Normative Specification (v0.5 Draft). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Scope & Objective

This specification details the multi-factor, explainable distributed risk calculation model used to score correlated incidents across the security fabric.

## 2. Five-Factor Linear Risk Model

The overall composite incident risk score $R \in [0, 100]$ is defined as an explicit, explainable weighted sum:

$$R = \min\left(100, \sum_{i=1}^{5} w_i \cdot S_i\right)$$

Where the signal vectors and default normalized weights are:

| Signal ($S_i$) | Component Name | Description | Default Weight ($w_i$) |
| :--- | :--- | :--- | :--- |
| $S_{\text{state}}$ | **State Integrity Signal** | Merkle root divergence, hash chain discontinuity, split-brain detected. | $0.35$ |
| $S_{\text{prov}}$ | **Provenance Signal** | Missing change management ticket, session hijack, untrusted origin. | $0.20$ |
| $S_{\text{beh}}$ | **Behavioral Signal** | Out-of-window mutation, velocity spike, scope expansion. | $0.20$ |
| $S_{\text{hist}}$ | **Historical Signal** | Prior security incidents associated with actor or service identity. | $0.10$ |
| $S_{\text{ext}}$ | **External Intel Signal** | AEGIS threat campaign correlation, compromised credential feed. | $0.15$ |

## 3. Explainability & Contribution Breakdown

Every evaluated risk score MUST provide an itemized contribution breakdown:

```typescript
export interface RiskScoreBreakdown {
  compositeScore: number; // 0..100
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: {
    stateIntegrity: { score: number; contribution: number; evidence: string };
    provenance: { score: number; contribution: number; evidence: string };
    behavioral: { score: number; contribution: number; evidence: string };
    historical: { score: number; contribution: number; evidence: string };
    externalIntel: { score: number; contribution: number; evidence: string };
  };
}
```

Implementations MUST NOT substitute opaque machine learning probabilities for the itemized factor breakdown.
