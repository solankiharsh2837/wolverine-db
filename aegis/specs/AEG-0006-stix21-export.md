# AEG-0006: OASIS STIX 2.1 JSON Export Specification

Status: Normative Specification (v0.1 Frozen).

## Overview

AEGIS exports candidates, indicators, and threat actor profiles as standard OASIS STIX 2.1 JSON bundles (`type: "bundle"`).

```json
{
  "type": "bundle",
  "id": "bundle--uuid-v4",
  "objects": [
    {
      "type": "threat-actor",
      "spec_version": "2.1",
      "id": "threat-actor--uuid-v4",
      "created": "2026-08-14T00:00:00.000Z",
      "modified": "2026-08-14T00:00:00.000Z",
      "name": "Candidate Operator Alpha",
      "aliases": ["alpha_dev", "alpha_pgp"],
      "confidence": 82
    }
  ]
}
```
