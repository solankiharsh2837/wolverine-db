# Performance

Measure rather than promise: write and read latency overhead, CPU, memory, history growth, checkpoint duration, Merkle build time, verification time, and recovery time. Benchmark datasets must state row size, write mix, protected scope, transaction concurrency, storage medium, and hardware.

v0.1 performance targets are **UNRESOLVED**. Optimizations must retain canonical ordering and verification equivalence; batching may reduce latency but must not weaken transaction boundaries or evidence durability.
