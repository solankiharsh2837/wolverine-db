import { describe, it, expect, beforeEach } from 'vitest';
import { LocalCheckpointStore } from '../../src/checkpoint/local.js';
import { S3CheckpointStore } from '../../src/checkpoint/s3.js';
import { WORMCheckpointStore } from '../../src/checkpoint/worm.js';
import { CheckpointAnchorEngine, computeCheckpointDigest } from '../../src/checkpoint/anchor.js';
import { AnchoredCheckpoint } from '../../src/checkpoint/types.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

describe('External Checkpoint Stores Properties (WDB-0011 Hardening)', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'wdb-chk-test-'));
  });

  const createSampleCheckpoint = (id: string, seq: bigint, rootHex: string): AnchoredCheckpoint => {
    const raw: Omit<AnchoredCheckpoint, 'digest'> = {
      checkpointId: id,
      scope: 'public.accounts',
      commitSeq: seq,
      previousCheckpointId: seq > 1n ? `chk-${Number(seq) - 1}` : null,
      merkleRoot: Buffer.from(rootHex, 'hex'),
      changeChainHead: Buffer.alloc(32, 0xaa),
      createdAtUs: 1723500000000000n + seq * 1000n,
      protocolVersion: 2,
    };
    const digest = computeCheckpointDigest(raw);
    return { ...raw, digest };
  };

  describe('LocalCheckpointStore', () => {
    it('property: enforces immutability and rejects conflicting checkpoint overwrite', async () => {
      const store = new LocalCheckpointStore(tmpDir);
      const chk1 = createSampleCheckpoint('00000000-0000-0000-0000-000000000001', 1n, '11'.repeat(32));

      await store.put(chk1);
      const fetched = await store.get(chk1.checkpointId);
      expect(fetched).not.toBeNull();
      expect(fetched?.commitSeq).toBe(1n);

      // Putting exact same checkpoint is idempotent
      await store.put(chk1);

      // Putting modified checkpoint with same ID throws conflict error
      const tamperedChk = createSampleCheckpoint('00000000-0000-0000-0000-000000000001', 1n, '22'.repeat(32));
      await expect(store.put(tamperedChk)).rejects.toThrow('CheckpointConflictError');
    });

    it('property: lists checkpoints in ascending sequence order', async () => {
      const store = new LocalCheckpointStore(tmpDir);
      const chk2 = createSampleCheckpoint('00000000-0000-0000-0000-000000000002', 2n, '22'.repeat(32));
      const chk1 = createSampleCheckpoint('00000000-0000-0000-0000-000000000001', 1n, '11'.repeat(32));

      await store.put(chk2);
      await store.put(chk1);

      const list = await store.list('public.accounts');
      expect(list).toHaveLength(2);
      expect(list[0].commitSeq).toBe(1n);
      expect(list[1].commitSeq).toBe(2n);
    });

    it('property: verifies digest integrity and detects local file tampering', async () => {
      const store = new LocalCheckpointStore(tmpDir);
      const chk = createSampleCheckpoint('00000000-0000-0000-0000-000000000003', 3n, '33'.repeat(32));
      await store.put(chk);

      expect(await store.verify(chk.checkpointId)).toBe(true);

      // Simulate malicious attacker modifying file on disk
      const filePath = path.join(tmpDir, `${chk.checkpointId}.wdbchk`);
      const fileData = await fs.readFile(filePath, 'utf8');
      const tamperedData = fileData.replace('"commitSeq": "3"', '"commitSeq": "999"');
      await fs.chmod(filePath, 0o666);
      await fs.writeFile(filePath, tamperedData, 'utf8');

      expect(await store.verify(chk.checkpointId)).toBe(false);
    });
  });

  describe('S3CheckpointStore', () => {
    it('property: enforces S3 Object Lock compliance immutability', async () => {
      const store = new S3CheckpointStore({ bucket: 'wdb-immutable-vault', objectLockEnabled: true });
      const chk = createSampleCheckpoint('00000000-0000-0000-0000-000000000010', 10n, 'aa'.repeat(32));

      await store.put(chk);
      const retrieved = await store.get(chk.checkpointId);
      expect(retrieved).not.toBeNull();
      expect(await store.verify(chk.checkpointId)).toBe(true);

      // Overwriting with different root violates Object Lock
      const tampered = createSampleCheckpoint('00000000-0000-0000-0000-000000000010', 10n, 'ff'.repeat(32));
      await expect(store.put(tampered)).rejects.toThrow('S3ObjectLockViolation');
    });
  });

  describe('WORMCheckpointStore', () => {
    it('property: enforces strict WORM retention and immutability', async () => {
      const store = new WORMCheckpointStore();
      const chk = createSampleCheckpoint('00000000-0000-0000-0000-000000000020', 20n, 'bb'.repeat(32));

      await store.put(chk);
      expect(await store.verify(chk.checkpointId)).toBe(true);

      const tampered = createSampleCheckpoint('00000000-0000-0000-0000-000000000020', 20n, 'cc'.repeat(32));
      await expect(store.put(tampered)).rejects.toThrow('WORMRetentionViolation');
    });
  });
});
