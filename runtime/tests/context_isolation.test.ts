import { describe, it, expect } from 'vitest';
import { runWithContext, getCurrentContext, buildAuthorizationEnvelope } from '../src/context/index.js';

describe('AsyncLocalStorage Context Isolation & Leak Suite', () => {
  it('proves 100% context isolation across 1,000 concurrent parallel async requests', async () => {
    const N_REQUESTS = 1_000;

    const tasks = Array.from({ length: N_REQUESTS }, (_, idx) => {
      const actorId = `actor_${idx}`;
      const sessionId = `session_${idx}`;
      const ticketId = `ticket_${idx}`;

      return new Promise<boolean>((resolve) => {
        runWithContext(
          {
            actorId,
            sessionId,
            ticketId,
            roles: [`role_${idx}`],
          },
          async () => {
            // Introduce variable async delay (simulating I/O, DB queries, remote API calls)
            const randomDelay = Math.floor(Math.random() * 15);
            await new Promise((r) => setTimeout(r, randomDelay));

            const ctx = getCurrentContext();
            const envelope = buildAuthorizationEnvelope();

            // Verify NO CONTEXT LEAKS: Request A MUST NEVER see Request B's identity
            const isIsolated =
              ctx?.actorId === actorId &&
              ctx?.sessionId === sessionId &&
              ctx?.ticketId === ticketId &&
              envelope.actor === actorId &&
              envelope.session === sessionId &&
              envelope.ticket === ticketId;

            resolve(isIsolated);
          }
        );
      });
    });

    const results = await Promise.all(tasks);
    const leakedCount = results.filter((valid) => !valid).length;

    expect(leakedCount).toBe(0);
    expect(results.length).toBe(N_REQUESTS);
  });
});
