# AEGIS Cyber Threat Intelligence Platform (v0.1.0 Stable Release)

AEGIS is an explainable Cyber Threat Intelligence (CTI) platform that collects, normalizes, extracts entities, correlates multi-source evidence, and generates actionable investigative leads with explicit evidence lineage.

It consumes state verification from **WolverineDB** (State Integrity) and behavioral telemetry from **Wolverine Runtime** (Execution Provenance), while using Wolverine technology to protect its own internal infrastructure.

---

## Complete Ecosystem Architectural Taxonomy

```text
                  WOLVERINE + AEGIS

 ┌────────────────────────────────────────┐
 │             WolverineDB                │
 │             (v0.1.0 Stable)            │
 │ STATE INTEGRITY                        │
 │                                        │
 │ Immutable history                      │
 │ Hash chains                            │
 │ Merkle verification                    │
 │ Recovery                               │
 └───────────────────┬────────────────────┘
                     │ state + provenance
 ┌───────────────────▼────────────────────┐
 │          Wolverine Runtime             │
 │             (v0.1.0 Stable)            │
 │ EXECUTION PROVENANCE                   │
 │                                        │
 │ Context                                │
 │ Authorization                          │
 │ Runtime observation                    │
 │ Incident telemetry                     │
 └───────────────────┬────────────────────┘
                     │ structured events
 ┌───────────────────▼────────────────────┐
 │                 AEGIS                  │
 │             (v0.1.0 Stable)            │
 │ INVESTIGATIVE INTELLIGENCE             │
 │                                        │
 │ Discovery                              │
 │ Collection                             │
 │ Evidence                               │
 │ Entities                               │
 │ Relationships                          │
 │ Correlation                            │
 │ AI Sentinel                            │
 └───────────────────┬────────────────────┘
                     │
                     ▼
               INVESTIGATOR
```

---

## Core Principles & Evaluation Boundaries

> [!IMPORTANT]
> **Key Scientific & Evaluation Distinctions**:
> 1. **Investigative Correlation Score $\neq$ Probability of Guilt**: Internal correlation scores (e.g. `82 / 100`) represent a policy-derived investigative score based on unique factor weights. They do **not** represent objective statistical probabilities of common ownership or legal proof of guilt.
> 2. **Similarity $\neq$ Identity**: Shared public VPN IPs, similar handle prefixes, or overlapping timezones accumulate as evidence but **never** force automatic identity resolution merging without unique cryptographic markers (e.g., PGP keys, wallet signatures, binary hashes).
> 3. **Dual Execution Planes**:
>    - `CONTROLLED_LAB_PLANE`: Uses synthetic ground-truth datasets to evaluate precision, recall, and false-positive resilience under known ground-truth conditions.
>    - `REAL_WORLD_PLANE`: Ingests public/lawful observations for investigative lead generation; ground truth is strictly marked `UNAVAILABLE`.
> 4. **Auditable AI Sentinel**: The AI Sentinel is strictly advisory (`decisionAuthority: "NONE"`). Every statement MUST cite source evidence IDs and preserve visible contradictions.
> 5. **Validation Scope**: Unit and integration tests validate protocol mechanisms, invariants, and deterministic software behavior; real-world attribution accuracy requires rigorous domain-specific evaluation and strict legal/operational controls.

---

## Complete Investigation Workflow (`aegis investigate`)

```text
Target Identifier
  ↓
Discovery (OSINT & Darknet feeds)
  ↓
Collection & Evidence Normalization
  ↓
WolverineDB State Integrity (SHA-256 Digest)
  ↓
Entity Extraction (Handles, IPs, Wallets, Artifacts)
  ↓
Entity Resolution
  ↓
Factor Aggregation (No Duplicate-Counting)
  ↓
Contradiction Analysis
  ↓
Correlation Policy
  ↓
Investigative Correlation Score
  ↓
Auditable AI Sentinel (Evidence Citations)
  ↓
OASIS STIX 2.1 JSON Export
```

---

## Quick Start & CLI Usage

### 1. Ingest Evidence
```bash
npx aegis ingest --type darkweb --uri "tor://market.onion/vendor/alpha" --payload '{"handle":"alpha","ip":"198.51.100.42"}'
```

### 2. Automated Target Investigation
```bash
npx aegis investigate --target "nocturne_operator" --plane lab
```

### 3. Check Self-Protection Status
```bash
npx aegis status
```

---

## License

MIT License.
