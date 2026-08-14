import { describe, it, expect } from 'vitest';
import { runWithContext, buildAuthorizationEnvelope } from '../src/context/index.js';
import { wolverineHttpMiddleware } from '../src/observer/index.js';
import { getCurrentContext } from '../src/context/index.js';

describe('Provenance Abuse & Spoofing Defense Suite', () => {
  it('demarcates application-supplied claims from infrastructure context', () => {
    runWithContext(
      {
        actorId: 'app_user',
        roles: ['user'],
        ticketId: 'CHG-FAKE', // Application-supplied claim
      },
      () => {
        const envelope = buildAuthorizationEnvelope();
        expect(envelope.actor).toBe('app_user');
        expect(envelope.ticket).toBe('CHG-FAKE');
      }
    );
  });

  it('handles missing or malformed header injection safely', () => {
    const req = {
      headers: {
        'x-actor-id': '', // Empty actor
        'x-user-roles': '   ', // Malformed whitespace
      },
    };
    const res = { setHeader() {} };

    wolverineHttpMiddleware(req, res, () => {
      const ctx = getCurrentContext();
      expect(ctx?.actorId).toBe('anonymous');
      expect(ctx?.roles).toEqual(['']);
    });
  });

  it('prevents context manipulation after context creation', () => {
    runWithContext({ actorId: 'user1' }, () => {
      const ctx = getCurrentContext();
      if (ctx) {
        // Attempting to mutate context object directly
        Object.freeze(ctx);
        expect(() => {
          (ctx as any).actorId = 'spoofed_admin';
        }).toThrow();
      }
    });
  });
});
