# AEGIS Controlled Laboratory Specification & Synthetic Manifest

## Overview

The **Controlled Laboratory** is an isolated, synthetic evaluation environment designed to demonstrate AEGIS attribution mechanisms against **known ground truth** without interacting with real-world threat actors or illegal dark-web services.

```text
                 CONTROLLED LABORATORY

             ┌──────────────────┐
             │ Marketplace Alpha│
             │   .onion service │
             └────────┬─────────┘
                      │
                      │ synthetic activity
                      ▼
             ┌──────────────────┐
             │ Marketplace Beta │
             │   .onion service │
             └────────┬─────────┘
                      │
                      ▼
                Tor Network
                      │
                      ▼
             AEGIS Collection
                      │
                      ▼
                  Evidence
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
    WolverineDB             AEGIS Engine
          │                       │
          └───────────┬───────────┘
                      ▼
              Investigator CLI
```

---

## Synthetic Data Manifest (100% Benign & Synthetic)

All personas, network addresses, wallet identifiers, and artifacts in the Controlled Laboratory are strictly synthetic:

| Entity Type | Synthetic Identifier | Standard / Space | Purpose |
|---|---|---|---|
| **Target Operator** | `nocturne_operator` | Synthetic Persona | Ground-truth threat actor |
| **Marketplace Alpha Handle** | `nocturne` | Synthetic Persona | Vendor alias on Market Alpha |
| **Marketplace Beta Handle** | `nocturne_2` | Synthetic Persona | Vendor alias on Market Beta |
| **OSINT Forum Handle** | `nocturne_dev` | Synthetic Persona | Forum developer persona |
| **C2 Infrastructure IP** | `198.51.100.42` | RFC 5737 TEST-NET-2 | Documentation address space |
| **Public VPN IP** | `203.0.113.1` | RFC 5737 TEST-NET-3 | Documentation address space |
| **Crypto Wallet Address** | `tb1qsynthetic0017labtestnetaddress99x` | Bitcoin Testnet (BIP-173) | Benign testnet address |
| **Binary Artifact Hash** | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | SHA-256 Digest | Shared script artifact hash |

---

## Controlled Relationship Mapping

```text
Alpha (Marketplace A)
 ├── Handle: nocturne
 ├── IP: 198.51.100.42
 ├── Wallet: tb1qsynthetic0017...
 └── Artifact: hash_script_X (e3b0c442...)
        │
        └──► [SHARED UNIQUE ARTIFACT & C2 INFRASTRUCTURE] ◄──┐
                                                             │
Beta (Marketplace B) ────────────────────────────────────────┘
 ├── Handle: nocturne_2
 ├── IP: 198.51.100.42
 └── Artifact: hash_script_X (e3b0c442...)
```

---

## Scientific Evaluation Boundary

- The Controlled Laboratory demonstrates that AEGIS's factor aggregation, entity resolution, and correlation graph algorithms correctly identify relationships against **known synthetic ground truth**.
- It does **not** make false claims of deanonymizing real-world actors.
