# Byzantine Quorum and Safety Theorem

This document outlines the formal mathematical safety bounds for the Wolverine Trust Plane.

## Parameters
- Cluster Size: $N = 5$
- Fault Tolerance: $f = \lfloor(N-1)/3\rfloor = 1$
- Quorum Threshold: $M = 4$ ($N - f$)

## Quorum Intersection
$$\text{Intersection} = |Q_1 \cap Q_2| \ge 2M - N = 2(4) - 5 = 3$$

Because at most $f=1$ node can be Byzantine, at least:
$$3 - 1 = 2 \text{ honest nodes}$$
are present in both quorums.

## Safety Invariant
Since honest nodes never attest conflicting digests for the same sequence, it is mathematically impossible for two conflicting commitments to achieve 4-of-5 finality certificates in the same epoch.
