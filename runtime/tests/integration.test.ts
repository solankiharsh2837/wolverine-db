import { describe, it, expect } from 'vitest';
import { wolverineHttpMiddleware, wrapPgQuery } from '../src/observer/index.js';
import { getCurrentContext } from '../src/context/index.js';

describe('Real Middleware & DB Client Integration Suite', () => {
  it('instruments HTTP request, creates context, and attaches envelope to DB query', async () => {
    const req = {
      headers: {
        'x-actor-id': 'operator_alice',
        'x-session-id': 'sess_9988',
        'x-user-roles': 'admin,dba',
        'x-change-ticket': 'CHG-7700',
        'x-operation-reason': 'Emergency DB fix',
      },
      url: '/api/v1/users',
      method: 'POST',
    };

    let responseHeaders: Record<string, string> = {};
    const res = {
      setHeader(name: string, value: string) {
        responseHeaders[name] = value;
      },
    };

    let queryExecuted = false;
    let queryEnvelope: Record<string, unknown> | undefined;

    // Simulate HTTP middleware execution
    await wolverineHttpMiddleware(req, res, async () => {
      const ctx = getCurrentContext();
      expect(ctx).toBeDefined();
      expect(ctx?.actorId).toBe('operator_alice');
      expect(ctx?.roles).toEqual(['admin', 'dba']);

      // Mock database query inside HTTP handler
      const mockPgQuery = async (sql: string) => {
        queryExecuted = true;
        return { rows: [{ id: 1, name: 'Alice' }] };
      };

      const res = await wrapPgQuery(mockPgQuery, 'SELECT * FROM users');
      queryEnvelope = res.envelope;
    });

    expect(responseHeaders['x-wolverine-request-id']).toBeDefined();
    expect(queryExecuted).toBe(true);
    expect(queryEnvelope).toBeDefined();
    expect(queryEnvelope?.actor).toBe('operator_alice');
    expect(queryEnvelope?.ticket).toBe('CHG-7700');
    expect(queryEnvelope?.reason).toBe('Emergency DB fix');
  });
});
