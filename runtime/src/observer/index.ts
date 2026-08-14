import { runWithContext, getCurrentContext, buildAuthorizationEnvelope } from '../context/index.js';

export interface HttpRequestLike {
  headers: Record<string, string | string[] | undefined>;
  url?: string;
  method?: string;
}

export interface HttpResponseLike {
  setHeader(name: string, value: string): void;
}

/**
 * HTTP Middleware for Express / Fastify / Node http server
 */
export function wolverineHttpMiddleware<T = void>(
  req: HttpRequestLike,
  res: HttpResponseLike,
  next: () => T
): T {
  const actorHeader = req.headers['x-actor-id'] || req.headers['x-user-id'];
  const actorId = Array.isArray(actorHeader) ? actorHeader[0] : actorHeader || 'anonymous';

  const sessionHeader = req.headers['x-session-id'];
  const sessionId = Array.isArray(sessionHeader) ? sessionHeader[0] : sessionHeader || undefined;

  const ticketHeader = req.headers['x-change-ticket'];
  const ticketId = Array.isArray(ticketHeader) ? ticketHeader[0] : ticketHeader || undefined;

  const reasonHeader = req.headers['x-operation-reason'];
  const reason = Array.isArray(reasonHeader) ? reasonHeader[0] : reasonHeader || undefined;

  const rolesHeader = req.headers['x-user-roles'];
  const rolesStr = Array.isArray(rolesHeader) ? rolesHeader[0] : rolesHeader || 'user';
  const roles = rolesStr.split(',').map((r) => r.trim());

  return runWithContext(
    {
      actorId,
      sessionId,
      roles,
      ticketId,
      reason,
      serviceName: 'web_api',
    },
    () => {
      const ctx = getCurrentContext();
      if (ctx && res.setHeader) {
        res.setHeader('x-wolverine-request-id', ctx.requestId);
      }
      return next();
    }
  );
}

/**
 * Database Query Wrapper for pg.Client / pg.Pool
 */
export function wrapPgQuery<T>(
  originalQueryFn: (sql: string, params?: unknown[]) => Promise<T>,
  sql: string,
  params?: unknown[]
): Promise<{ result: T; envelope: Record<string, unknown> }> {
  const envelope = buildAuthorizationEnvelope();
  return originalQueryFn(sql, params).then((result) => ({
    result,
    envelope,
  }));
}
