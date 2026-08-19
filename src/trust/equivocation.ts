import crypto from 'node:crypto';
import { canonicalizeJson } from '../binary/c14n.js';

export interface EquivocationEvidence {
  evidenceType: 'EQUIVOCATION_DETECTED';
  validatorId: string;
  tenantId: string;
  databaseId: string;
  epoch: number;
  commitSeq: bigint;
  observedDigestAHex: string;
  observedDigestBHex: string;
  detectedAtUs: bigint;
  evidenceDigestHex: string;
}

export function createEquivocationEvidence(
  validatorId: string,
  tenantId: string,
  databaseId: string,
  epoch: number,
  commitSeq: bigint,
  digestAHex: string,
  digestBHex: string
): EquivocationEvidence {
  const detectedAtUs = BigInt(Date.now()) * 1000n;
  const rawPayload = {
    evidenceType: 'EQUIVOCATION_DETECTED',
    validatorId,
    tenantId,
    databaseId,
    epoch,
    commitSeq: commitSeq.toString(),
    observedDigestAHex: digestAHex,
    observedDigestBHex: digestBHex,
    detectedAtUs: detectedAtUs.toString(),
  };

  const canonicalJson = canonicalizeJson(rawPayload);
  const evidenceDigest = crypto
    .createHash('sha256')
    .update(Buffer.from(`WDB:SLASH_EVIDENCE:v1:${canonicalJson}`, 'utf8'))
    .digest();

  return {
    evidenceType: 'EQUIVOCATION_DETECTED',
    validatorId,
    tenantId,
    databaseId,
    epoch,
    commitSeq,
    observedDigestAHex: digestAHex,
    observedDigestBHex: digestBHex,
    detectedAtUs,
    evidenceDigestHex: evidenceDigest.toString('hex'),
  };
}
