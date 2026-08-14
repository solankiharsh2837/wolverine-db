# AEGIS & Wolverine Unified Demonstration Guide

## Presentation Framing

> **“We built a layered cyber-investigation system where evidence integrity, execution provenance, and threat intelligence are independently verifiable.”**

### Presentation Terminology Rules

- **Use**: *“AEGIS generates investigative leads.”*
- **Do Not Use**: *“AEGIS identifies criminals.”*
- **Use**: *“The controlled laboratory demonstrates attribution mechanisms against known ground truth.”*
- **Do Not Use**: *“This proves the system can deanonymize real criminals.”*

---

## 10-Step Live Demonstration Walkthrough

### Step 1: Self-Protection & Infrastructure Audit
Verify that AEGIS's own PostgreSQL database is protected by WolverineDB and microservices are observed by Wolverine Runtime:
```bash
npx aegis status
```

### Step 2: Automated Target Investigation
Run automated darknet feed discovery and evidence collection:
```bash
npx aegis investigate --target nocturne_operator --plane lab
```

### Step 3: Interactive Case Overview
View the visual terminal case overview and correlation progress bar:
```bash
npx aegis case show CASE-2026-0017
```

### Step 4: Evidence Inspection & Cryptographic Digest
Inspect individual evidence records and their SHA-256 state binding:
```bash
npx aegis evidence show EV-00182
```

### Step 5: Entity Graph Inspection
Inspect extracted graph nodes across handles, infrastructure, wallets, and artifacts:
```bash
npx aegis entity show nocturne
```

### Step 6: ASCII Relationship Network Visualization
Render the relationship network connecting Marketplaces Alpha, Beta, and OSINT:
```bash
npx aegis graph nocturne_operator
```

### Step 7: Factor Attribution Explanation
Deep-dive into factor weighting and evidence citations:
```bash
npx aegis explain CANDIDATE-12
```

### Step 8: Auditable AI Sentinel Hypothesis
Review AI Sentinel hypothesis with explicit citations and `decisionAuthority: "NONE"`.

### Step 9: OASIS STIX 2.1 Threat Actor Bundle Export
Export the completed investigation as a standard STIX 2.1 JSON bundle:
```bash
npx aegis export CANDIDATE-12 --format stix21
```

### Step 10: Live Database Tamper & Selective Recovery Demonstration
Demonstrate state integrity failure and non-destructive approval-gated recovery:
```bash
# 1. Verify clean database state
npx wdb verify --scope aegis.evidence_records

# 2. Tamper database row directly
# 3. Re-verify -> Detects MERKLE_ROOT_MISMATCH
npx wdb verify --scope aegis.evidence_records

# 4. Generate recovery proposal & execute with Ed25519 approval envelope
# 5. Clean state restored
npx wdb verify --scope aegis.evidence_records
```

---

## Unified Demo Script Execution

Run the complete 3-act unified demonstration in a single command:
```bash
npx tsx aegis/benches/unified_ecosystem_demo.ts
```
