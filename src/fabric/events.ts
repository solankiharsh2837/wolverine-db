import crypto from 'node:crypto';
import { SecurityEventEnvelope, SecurityPlane, SecurityEventType } from './types.js';
import { canonicalizeJson } from '../binary/c14n.js';

export function computeEventEvidenceHash(payload: Record<string, unknown>): Buffer {
  const domain = Buffer.from('WDB:EVENT_EVIDENCE:v1:', 'utf8');
  const canonicalJsonStr = canonicalizeJson(payload);
  const jsonBuf = Buffer.from(canonicalJsonStr, 'utf8');
  return crypto.createHash('sha256').update(Buffer.concat([domain, jsonBuf])).digest();
}

export function createSecurityEvent(params: {
  plane: SecurityPlane;
  eventType: SecurityEventType;
  actorId: string;
  serviceId: string;
  scope: string;
  payload: Record<string, unknown>;
  traceId?: string;
}): SecurityEventEnvelope {
  const eventId = crypto.randomUUID();
  const timestampUs = BigInt(Date.now()) * 1000n;
  const evidenceHash = computeEventEvidenceHash(params.payload);

  return {
    eventId,
    plane: params.plane,
    eventType: params.eventType,
    timestampUs,
    actorId: params.actorId,
    serviceId: params.serviceId,
    traceId: params.traceId,
    scope: params.scope,
    payload: params.payload,
    evidenceHash,
  };
}

export function computeDistributedIncidentId(
  originPlane: SecurityPlane,
  rootEventId: string,
  timestampUs: bigint,
  scope: string
): string {
  const domain = Buffer.from('WDB:INCIDENT_ID:v1:', 'utf8');
  const planeBuf = Buffer.from(originPlane, 'utf8');
  const planeLenBuf = Buffer.alloc(4);
  planeLenBuf.writeUInt32BE(planeBuf.length, 0);

  const rootEventBuf = Buffer.alloc(16);
  Buffer.from(rootEventId.replace(/-/g, ''), 'hex').copy(rootEventBuf, 0);

  const timeBuf = Buffer.alloc(8);
  timeBuf.writeBigInt64BE(timestampUs, 0);

  const scopeBuf = Buffer.from(scope, 'utf8');
  const scopeLenBuf = Buffer.alloc(4);
  scopeLenBuf.writeUInt32BE(scopeBuf.length, 0);

  const preimage = Buffer.concat([
    domain,
    planeLenBuf,
    planeBuf,
    rootEventBuf,
    timeBuf,
    scopeLenBuf,
    scopeBuf,
  ]);
  const digest = crypto.createHash('sha256').update(preimage).digest();
  const hexSuffix = digest.subarray(0, 8).toString('hex');

  const dateStr = new Date(Number(timestampUs / 1000n))
    .toISOString()
    .slice(0, 10)
    .replace(/-/g, '');

  return `inc:${dateStr}:${originPlane.toLowerCase()}:${hexSuffix}`;
}
