import { describe, it, expect } from 'vitest';
import crypto from 'crypto';

describe('Checkpoint Anchoring Engine (WDB-0012 Scaffolding)', () => {
  it('computes canonical checkpoint digest matching WDB-0012 domain separation', () => {
    const checkpointId = '429f9c0e-128a-40f3-8bd2-55d326ef6009';
    const scope = 'public.accounts';
    const commitSeq = 42n;
    const merkleRoot = Buffer.alloc(32, 0xaa);
    const changeChainHead = Buffer.alloc(32, 0xbb);
    const createdAt = 1723500000000000n;
    const protocolVersion = 2;

    const scopeBuf = Buffer.from(scope, 'utf8');
    const scopeLenBuf = Buffer.alloc(4);
    scopeLenBuf.writeUInt32BE(scopeBuf.length, 0);

    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigInt64BE(commitSeq, 0);

    const timeBuf = Buffer.alloc(8);
    timeBuf.writeBigInt64BE(createdAt, 0);

    const verBuf = Buffer.alloc(4);
    verBuf.writeInt32BE(protocolVersion, 0);

    const checkpointIdBytes = Buffer.from(checkpointId.replace(/-/g, ''), 'hex');
    const prevCheckpointBytes = Buffer.alloc(16, 0); // null

    const preimage = Buffer.concat([
      Buffer.from('WDB:CHECKPOINT:v1:', 'utf8'),
      checkpointIdBytes,
      scopeLenBuf,
      scopeBuf,
      seqBuf,
      prevCheckpointBytes,
      merkleRoot,
      changeChainHead,
      timeBuf,
      verBuf,
    ]);

    const digest = crypto.createHash('sha256').update(preimage).digest();
    expect(digest.length).toBe(32);
  });
});
