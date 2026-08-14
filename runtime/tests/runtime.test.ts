import { describe, it, expect } from 'vitest';
import { runWithContext, getCurrentContext, buildAuthorizationEnvelope } from '../src/context/index.js';
import { IncidentEngine } from '../src/incidents/index.js';
import { WolverineDBBridge, WolverineDBClient } from '../src/bridge/index.js';

describe('Wolverine Runtime (.js / .ts) v0.1 Suite', () => {
  it('propagates execution context via AsyncLocalStorage', () => {
    runWithContext(
      { actorId: 'admin_user', roles: ['admin'], sessionId: 'sess_123', ticketId: 'CHG-9900', reason: 'System Maintenance' },
      () => {
        const ctx = getCurrentContext();
        expect(ctx).toBeDefined();
        expect(ctx?.actorId).toBe('admin_user');
        expect(ctx?.roles).toContain('admin');
        expect(ctx?.ticketId).toBe('CHG-9900');

        const envelope = buildAuthorizationEnvelope();
        expect(envelope.actor).toBe('admin_user');
        expect(envelope.ticket).toBe('CHG-9900');
        expect(envelope.reason).toBe('System Maintenance');
      }
    );
  });

  it('generates UNKNOWN envelope when no context is active', () => {
    const envelope = buildAuthorizationEnvelope();
    expect(envelope.actor).toBe('UNKNOWN');
  });

  it('creates structured IncidentReport with stack traces and severity', () => {
    runWithContext({ actorId: 'operator1', serviceName: 'order_service' }, () => {
      const incident = IncidentEngine.createReport('CRITICAL', 'UNAUTHORIZED_MUTATION', { table: 'public.orders' });
      expect(incident.severity).toBe('CRITICAL');
      expect(incident.eventType).toBe('UNAUTHORIZED_MUTATION');
      expect(incident.actor).toBe('operator1');
      expect(incident.service).toBe('order_service');
      expect(incident.stackTrace).toBeDefined();
    });
  });

  it('bridges runtime incident reporting with WolverineDB state verification interface', async () => {
    const mockDb: WolverineDBClient = {
      async verify(scope?: string) {
        return {
          status: 'VALID',
          checkedRecordsCount: 1,
          verifiedScope: scope || 'all',
        };
      },
    };
    const bridge = new WolverineDBBridge(mockDb);

    const result = await bridge.auditAndVerifyScope('public.users');
    expect(result.verification.status).toBe('VALID');
    expect(result.incident).toBeUndefined();
  });
});
