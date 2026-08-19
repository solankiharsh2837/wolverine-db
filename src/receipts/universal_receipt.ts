import crypto from 'node:crypto';
import { canonicalizeJson } from '../binary/c14n.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export interface EvidencePlaneReceiptData {
  checkpointId: string;
  commitSeq: string; // stringified bigint
  lsn: string;
  checkpointDigestHex: string;
  stateMerkleRootHex: string;
  changeChainHeadHex: string;
  agentAttestationHex: string;
  customerAuthorizationHex: string;
}

export interface TrustPlaneReceiptData {
  networkId: string; // e.g. 'wolverine-besu-cluster'
  chainId: number; // e.g. 13370
  blockchainTransactionHash: `0x${string}` | string;
  blockNumber: string; // stringified bigint
  blockHash: `0x${string}` | string;
  finalityStatus: 'FINALIZED' | 'PENDING' | 'REJECTED';
  contractAddress: `0x${string}` | string;
  contractEventDataHex?: string;
  previousCommitmentDigestHex: string;
}

export interface OptionalPublicAnchorData {
  status: 'NONE' | 'PENDING' | 'INCLUDED' | 'FINALIZED';
  chainId?: number;
  txHash?: string;
  blockNumber?: string;
  anchorRootHex?: string;
}

export interface UniversalTrustReceipt {
  receiptVersion: number; // 2
  receiptId: string;
  tenantId: string;
  databaseId: string;
  timestampUs: string; // stringified bigint
  evidencePlane: EvidencePlaneReceiptData;
  trustPlane: TrustPlaneReceiptData;
  optionalPublicAnchor: OptionalPublicAnchorData;
  receiptDigestHex: string;
}

export function computeReceiptDigest(
  receipt: Omit<UniversalTrustReceipt, 'receiptDigestHex'>
): Buffer {
  const domain = Buffer.from('WDB:UNIVERSAL_RECEIPT:v2:', 'utf8');
  const canonicalJson = canonicalizeJson({
    receiptVersion: receipt.receiptVersion,
    receiptId: receipt.receiptId,
    tenantId: receipt.tenantId,
    databaseId: receipt.databaseId,
    timestampUs: receipt.timestampUs,
    evidencePlane: receipt.evidencePlane,
    trustPlane: receipt.trustPlane,
    optionalPublicAnchor: receipt.optionalPublicAnchor,
  });

  return crypto
    .createHash('sha256')
    .update(Buffer.concat([domain, Buffer.from(canonicalJson, 'utf8')]))
    .digest();
}

export class UniversalTrustReceiptGenerator {
  public static createReceipt(params: {
    tenantId: string;
    databaseId: string;
    evidencePlane: EvidencePlaneReceiptData;
    trustPlane: TrustPlaneReceiptData;
    optionalPublicAnchor?: OptionalPublicAnchorData;
  }): UniversalTrustReceipt {
    const timestampUs = (BigInt(Date.now()) * 1000n).toString();
    const receiptId = crypto.randomUUID();

    const base = {
      receiptVersion: 2,
      receiptId,
      tenantId: params.tenantId,
      databaseId: params.databaseId,
      timestampUs,
      evidencePlane: params.evidencePlane,
      trustPlane: params.trustPlane,
      optionalPublicAnchor: params.optionalPublicAnchor ?? { status: 'NONE' },
    };

    const digest = computeReceiptDigest(base);

    return {
      ...base,
      receiptDigestHex: digest.toString('hex'),
    };
  }
}
