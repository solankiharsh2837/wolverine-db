import { AsyncLocalStorage } from 'node:async_hooks';
import crypto from 'node:crypto';

export interface WolverineContextOptions {
  actorId: string;
  roles?: string[];
  sessionId?: string;
  serviceName?: string;
  ticketId?: string;
  reason?: string;
}

export interface WolverineContext {
  requestId: string;
  sessionId: string;
  actorId: string;
  roles: string[];
  serviceName: string;
  startTimestampUs: bigint;
  ticketId?: string;
  reason?: string;
}

const asyncLocalStorage = new AsyncLocalStorage<WolverineContext>();

export function runWithContext<T>(options: WolverineContextOptions, fn: () => T): T {
  const context: WolverineContext = {
    requestId: crypto.randomUUID(),
    sessionId: options.sessionId || 'anon_session',
    actorId: options.actorId,
    roles: options.roles || ['user'],
    serviceName: options.serviceName || 'app_service',
    startTimestampUs: BigInt(Date.now() * 1000),
    ticketId: options.ticketId,
    reason: options.reason,
  };

  return asyncLocalStorage.run(context, fn);
}

export function getCurrentContext(): WolverineContext | undefined {
  return asyncLocalStorage.getStore();
}

/**
 * Builds canonical JSON AuthorizationEnvelope matching WDB-0002 Tag 9
 */
export function buildAuthorizationEnvelope(): Record<string, unknown> {
  const ctx = getCurrentContext();
  if (!ctx) {
    return {
      actor: 'UNKNOWN',
      identity: { roles: ['unauthenticated'] },
      session: 'none',
      request: 'none',
      service: 'unregistered',
      timestamp: Date.now() * 1000,
    };
  }

  const envelope: Record<string, unknown> = {
    actor: ctx.actorId,
    identity: { roles: ctx.roles },
    session: ctx.sessionId,
    request: ctx.requestId,
    service: ctx.serviceName,
    timestamp: Number(ctx.startTimestampUs),
  };

  if (ctx.ticketId) envelope.ticket = ctx.ticketId;
  if (ctx.reason) envelope.reason = ctx.reason;

  return envelope;
}
