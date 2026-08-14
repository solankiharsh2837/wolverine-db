# WRT-0002: Behavioral Execution Observer

Status: Normative Specification (v0.1 Frozen).

## Overview

The Execution Observer intercepts application boundaries (HTTP request handlers, RPC endpoints, database client queries) to capture behavioral metrics and execution invariants.

## Instrumentation Contracts

1. **HTTP Framework Interception**:
   - Intercepts incoming HTTP requests (Express, Fastify, NestJS).
   - Establishes `WolverineContext` from request headers (`x-wolverine-request-id`, `authorization`, `x-change-ticket`).
   - Audits response status codes, execution duration, and exception events.

2. **Database Driver Interception**:
   - Wraps database client query methods (`pg.Pool.query`, `pg.Client.query`).
   - Injects current `WolverineContext` authorization provenance envelope into PostgreSQL transaction context.
   - Monitors query execution duration and row count anomalies.
