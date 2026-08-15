# WDB-0101: Byzantine Quorum and Safety Theorem Protocol

Status: Normative Specification (v1.0.0 Frozen Protocol). The normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as requirements.

## 1. Mathematical Quorum Parameters

For a validator set of size $N$:

- Maximum tolerable Byzantine (malicious / faulty) nodes: $f = \left\lfloor \frac{N - 1}{3} \right\rfloor$.
- Required Quorum Threshold: $M \ge N - f$.
- For standard cluster $N = 5$:
  - $f = \left\lfloor \frac{5 - 1}{3} \right\rfloor = 1$.
  - Required Quorum $M = 5 - 1 = 4$ ($4$-of-$5$).

## 2. Quorum Intersection Theorem (Safety Proof)

Let $Q_1$ and $Q_2$ be any two valid finality quorums of size $\ge M$:

$$|Q_1 \cap Q_2| = |Q_1| + |Q_2| - |Q_1 \cup Q_2| \ge 2M - N$$

For $N = 5, M = 4$:

$$|Q_1 \cap Q_2| \ge 2(4) - 5 = 8 - 5 = 3$$

Since the total number of Byzantine nodes is at most $f = 1$, the intersection contains at least:

$$|Q_1 \cap Q_2| - f \ge 3 - 1 = 2 \text{ honest, non-faulty validators.}$$

## 3. Formal Safety Theorem

**Theorem 1 (Non-Equivocation Safety)**:
*No two conflicting commitments $C_A \ne C_B$ for the same tuple $(\text{tenantId}, \text{databaseId}, \text{commitSeq})$ may both obtain valid Quorum Certificates in the same epoch unless the Byzantine fault threshold is violated ($> f$ malicious nodes).*

**Proof**:
Assume for contradiction that both $C_A$ and $C_B$ obtain valid quorums $Q_A$ and $Q_B$ with $|Q_A| \ge 4$ and $|Q_B| \ge 4$.
By the Quorum Intersection Theorem, $|Q_A \cap Q_B| \ge 3$.
Since at most $f=1$ node is Byzantine, at least $3 - 1 = 2$ nodes in the intersection are honest.
An honest node strictly executes monotonic attestation and rejects $C_B$ if it already attested $C_A$ at that sequence.
Thus, honest nodes will not double-sign, contradicting the assumption that $Q_B$ reached quorum. $\blacksquare$
