# WRT-0001: Context Propagation & Provenance Builder

Status: Normative Specification (v0.1 Frozen).

## Overview

Wolverine Runtime MUST maintain an asynchronous execution context across HTTP requests, RPC calls, database queries, and async task boundaries.

## Context Structure

The runtime context (`WolverineContext`) MUST contain:
- `requestId`: UUID v4 (16 bytes)
- `sessionId`: String (UTF8)
- `actorId`: String (UTF8)
- `identity`: Record containing authenticated roles and permissions
- `serviceName`: String (UTF8)
- `startTimestampUs`: Signed 64-bit Unix microseconds UTC
- `ticketId`: Optional change ticket reference string
- `reason`: Optional operation justification string

## WolverineDB Provenance Envelope Generation

When a database operation is triggered within a `WolverineContext`, the context builder MUST generate a canonical JSON `AuthorizationEnvelope` matching WDB-0002 Tag 9:

```json
{
  "actor": "actorId",
  "identity": { "roles": ["admin"] },
  "session": "sessionId",
  "request": "requestId",
  "service": "serviceName",
  "timestamp": 1800000000000000,
  "ticket": "CHG-1001",
  "reason": "Routine update"
}
```

If no `WolverineContext` is active, database operations MUST produce an envelope marked `"actor": "UNKNOWN"`, which WolverineDB verifier engines will classify as `UNAUTHORIZED` or `UNKNOWN`.
