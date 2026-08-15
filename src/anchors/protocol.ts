import crypto from 'node:crypto';
import { AnchorRecord } from './types.js';

export function computeAnchorCommitmentDigest(
  params: Pick<AnchorRecord, 'domainType' | 'chainId' | 'checkpointId' | 'checkpointDigest' | 'commitSeq' | 'timestampUs'>
): Buffer {
  const domain = Buffer.from('WDB:ANCHOR:v1:', 'utf8');

  const domainTypeBuf = Buffer.alloc(2);
  domainTypeBuf.writeUInt16BE(params.domainType, 0);

  const chainIdBytes = Buffer.from(params.chainId, 'utf8');
  const chainIdLenBuf = Buffer.alloc(2);
  chainIdLenBuf.writeUInt16BE(chainIdBytes.length, 0);

  const checkpointIdBytes = Buffer.alloc(16);
  Buffer.from(params.checkpointId.replace(/-/g, ''), 'hex').copy(checkpointIdBytes, 0);

  const checkpointDigestBuf = Buffer.isBuffer(params.checkpointDigest)
    ? params.checkpointDigest
    : Buffer.from((params.checkpointDigest as any), 'hex');

  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigInt64BE(BigInt(params.commitSeq), 0);

  const timeBuf = Buffer.alloc(8);
  timeBuf.writeBigInt64BE(BigInt(params.timestampUs), 0);

  const preimage = Buffer.concat([
    domain,
    domainTypeBuf,
    chainIdLenBuf,
    chainIdBytes,
    checkpointIdBytes,
    checkpointDigestBuf,
    seqBuf,
    timeBuf,
  ]);

  return crypto.createHash('sha256').update(preimage).digest();
}
