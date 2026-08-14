import crypto from 'node:crypto';

export interface EvidenceRecord {
  evidenceId: string;
  sourceType: 'OSINT' | 'DARKWEB' | 'TELEMETRY' | 'LAB_SYNTHETIC';
  sourceUri: string;
  collectedAtUs: bigint;
  payloadHash: Buffer;
  rawPayload: string;
  metadata: Record<string, unknown>;
}

export class EvidenceManager {
  public static createEvidenceRecord(
    sourceType: EvidenceRecord['sourceType'],
    sourceUri: string,
    rawPayload: string,
    metadata: Record<string, unknown> = {}
  ): EvidenceRecord {
    const payloadHash = crypto.createHash('sha256').update(rawPayload, 'utf8').digest();
    return {
      evidenceId: crypto.randomUUID(),
      sourceType,
      sourceUri,
      collectedAtUs: BigInt(Date.now() * 1000),
      payloadHash,
      rawPayload,
      metadata,
    };
  }
}
