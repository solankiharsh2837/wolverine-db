# Wolverine Runtime (.js / .ts) (v0.1.0 Stable)

Wolverine Runtime provides behavioral security, execution observability, context propagation, and structured incident reporting for Node.js and TypeScript application runtimes.

While **WolverineDB protects state**, **Wolverine Runtime protects behavior**, and **AEGIS understands threats**.

---

## Architectural Taxonomy

```text
                 WOLVERINE ECOSYSTEM

        ┌───────────────────────────┐
        │       WolverineDB         │
        │       (v0.1.0 Stable)     │
        │   PROTECTS STATE          │
        │                           │
        │ History                   │
        │ Hash chains               │
        │ Merkle verification       │
        │ Recovery                  │
        └─────────────┬─────────────┘
                      │ state + provenance
                      ▼
        ┌───────────────────────────┐
        │    Wolverine Runtime      │
        │       (v0.1.0 Stable)     │
        │   PROTECTS BEHAVIOR       │
        │                           │
        │ Context                   │
        │ Execution observation     │
        │ Provenance                │
        │ Incidents                 │
        │ Telemetry                 │
        └─────────────┬─────────────┘
                      │ structured events
                      ▼
        ┌───────────────────────────┐
        │          AEGIS            │
        │                           │
        │   UNDERSTANDS THREATS     │
        │                           │
        │ Correlation               │
        │ Intelligence              │
        │ Anomaly analysis          │
        │ AI Sentinel               │
        └───────────────────────────┘
```

---

## Features (v0.1.0 Stable)

- **AsyncLocalStorage Context Propagation (WRT-0001)**: 100% isolated context propagation across async/await boundaries, HTTP handlers, and database queries (**0 context leaks** verified under 1,000 parallel async requests).
- **WolverineDB Provenance Builder**: Generates WDB-0002 Tag 9 canonical authorization envelopes (`actor`, `identity`, `session`, `request`, `service`, `timestamp`, `ticket`, `reason`).
- **Deterministic Incident Engine (WRT-0003)**: Classifies execution events as `NORMAL`, `SUSPICIOUS`, or `CRITICAL` with structured stack traces (**100% deterministic, zero LLM dependencies** in runtime core).
- **WolverineDB Bridge & AEGIS Telemetry (WRT-0004)**: Interface-decoupled bridge linking runtime behavioral anomalies to `WolverineDB.verify()` checks and AEGIS threat intelligence streams.

---

## Benchmark Methodology & Environmental Caveats

> [!NOTE]
> Benchmark results represent performance within our tested synthetic suite and Node.js v25 environment. They demonstrate sub-microsecond context efficiency, but should be evaluated against your application's framework middleware stack and production concurrency.

- **AsyncLocalStorage Context Establishment**: **1,143,868 contexts/sec** (0.874 $\mu$s / request)
- **`AuthorizationEnvelope` Serialization**: **13,976,436 envelopes/sec** (0.072 $\mu$s / envelope)
- **HTTP Middleware Interception**: **1,137,820 requests/sec** (0.878 $\mu$s / request)
- **Incident Report Creation**: **20,269 reports/sec** (with stack trace capture)

---

## License

MIT License.
