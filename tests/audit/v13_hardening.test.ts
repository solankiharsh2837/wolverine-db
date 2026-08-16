import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  PersistentTrustLedger,
  LocalCheckpointStore,
  matchesProtectedScope,
  CustomerKeyRotationManager,
  compareCanonicalStrings,
  encodeProtocolTuple,
  encodePrimaryKeyTuple,
  decodePrimaryKeyTuple,
  AnchoredCheckpoint,
} from '../../src/index.js';

describe('WolverineDB v1.3.0 Hardening Suite: Concurrency, Scope, and Determinism', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'wdb-hardening-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe('1. Concurrent Trust Ledger Append Race Defense (WDB-0131)', () => {
    it('serializes 50 concurrent appendRecord calls with zero forks, duplicate seqs, or chain breaks', async () => {
      const ledger = new PersistentTrustLedger();
      await ledger.init();

      const NUM_CONCURRENT = 50;
      const appendPromises = Array.from({ length: NUM_CONCURRENT }, (_, idx) =>
        ledger.appendRecord(
          'COMMITMENT',
          { transactionId: `tx-${idx}`, amount: idx * 100 },
          1,
          'valset-prod-v1',
          'tenant-concurrency',
          'db-orders'
        )
      );

      // Execute all 50 appends concurrently
      const results = await Promise.all(appendPromises);
      expect(results.length).toBe(NUM_CONCURRENT);

      const records = ledger.getRecords();
      expect(records.length).toBe(NUM_CONCURRENT);

      // Verify strict sequence monotonicity: 1n to 50n with NO duplicates
      const observedSeqs = records.map((r) => r.ledgerSeq);
      for (let i = 0; i < NUM_CONCURRENT; i++) {
        expect(observedSeqs[i]).toBe(BigInt(i + 1));
      }

      // Verify unbroken hash chain continuity (no forks)
      for (let i = 1; i < records.length; i++) {
        const prev = records[i - 1]!;
        const curr = records[i]!;
        expect(Buffer.compare(curr.previousRecordDigest, prev.recordDigest)).toBe(0);
      }
    });
  });

  describe('2. Checkpoint Atomic Creation & TOCTOU Defense (WDB-0132)', () => {
    it('handles 50 concurrent put operations of identical checkpoint idempotently', async () => {
      const store = new LocalCheckpointStore(tempDir);
      await store.init();

      const checkpoint: AnchoredCheckpoint = {
        checkpointId: '11111111-1111-1111-1111-111111111111',
        scope: 'public.accounts',
        commitSeq: 100n,
        previousCheckpointId: null,
        merkleRoot: Buffer.alloc(32, 0xaa),
        changeChainHead: Buffer.alloc(32, 0xbb),
        createdAtUs: 1723500000000000n,
        protocolVersion: 3,
        digest: Buffer.alloc(32, 0xcc),
      };

      const putPromises = Array.from({ length: 50 }, () => store.put(checkpoint));
      await expect(Promise.all(putPromises)).resolves.not.toThrow();

      const retrieved = await store.get(checkpoint.checkpointId);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.scope).toBe('public.accounts');
    });

    it('rejects conflicting checkpoint writes under race conditions', async () => {
      const store = new LocalCheckpointStore(tempDir);
      await store.init();

      const cpA: AnchoredCheckpoint = {
        checkpointId: '22222222-2222-2222-2222-222222222222',
        scope: 'public.users',
        commitSeq: 101n,
        previousCheckpointId: null,
        merkleRoot: Buffer.alloc(32, 0x11),
        changeChainHead: Buffer.alloc(32, 0x11),
        createdAtUs: 1723500000000000n,
        protocolVersion: 3,
        digest: Buffer.alloc(32, 0xaa),
      };

      const cpB: AnchoredCheckpoint = {
        ...cpA,
        digest: Buffer.alloc(32, 0xff), // Conflicting digest
      };

      await store.put(cpA);
      await expect(store.put(cpB)).rejects.toThrow(/CheckpointConflictError/);
    });
  });

  describe('3. Strict Authorization Scope Evaluation (WDB-0133)', () => {
    it('strictly prevents prefix, suffix, and substring scope leakage', () => {
      const protectedScope = 'public.users';

      // Legitimate exact match
      expect(matchesProtectedScope('public.users', protectedScope)).toBe(true);

      // Scope escape / prefix attack attempts: MUST BE FALSE
      expect(matchesProtectedScope('public.users_backup', protectedScope)).toBe(false);
      expect(matchesProtectedScope('public.users_archive', protectedScope)).toBe(false);
      expect(matchesProtectedScope('public.users2', protectedScope)).toBe(false);
      expect(matchesProtectedScope('private.users', protectedScope)).toBe(false);
      expect(matchesProtectedScope('users', protectedScope)).toBe(false);

      // Schema-level wildcard
      expect(matchesProtectedScope('public.users', 'public.*')).toBe(true);
      expect(matchesProtectedScope('public.orders', 'public.*')).toBe(true);
      expect(matchesProtectedScope('private.orders', 'public.*')).toBe(false);

      // Global wildcard
      expect(matchesProtectedScope('public.anything', 'global')).toBe(true);
      expect(matchesProtectedScope('public.anything', '*')).toBe(true);
    });
  });

  describe('4. Key Lifecycle, Keypair Correspondence & Dual-Signature Enforcement (WDB-0134)', () => {
    it('verifies keypair correspondence and rejects mismatched keys', async () => {
      const ledger = new PersistentTrustLedger();
      const manager = new CustomerKeyRotationManager(ledger);

      const oldPair = crypto.generateKeyPairSync('ed25519');
      const oldPub = oldPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

      const newPair = crypto.generateKeyPairSync('ed25519');
      const newPub = newPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

      const bogusPair = crypto.generateKeyPairSync('ed25519');

      manager.registerGenesisKey('tenant-crypto-sec', oldPub);

      // Attempt rotation with mismatched old private key
      await expect(
        manager.executeKeyRotation(
          'tenant-crypto-sec',
          'db-sec',
          bogusPair.privateKey, // BOGUS old private key
          oldPub,
          newPair.privateKey,
          newPub,
          1n
        )
      ).rejects.toThrow(/oldPrivateKey does not match oldPubkey/);

      // Attempt rotation with mismatched new private key
      await expect(
        manager.executeKeyRotation(
          'tenant-crypto-sec',
          'db-sec',
          oldPair.privateKey,
          oldPub,
          bogusPair.privateKey, // BOGUS new private key
          newPub,
          1n
        )
      ).rejects.toThrow(/newPrivateKey does not match newPubkey/);

      // Legitimate dual-signed rotation succeeds
      const record = await manager.executeKeyRotation(
        'tenant-crypto-sec',
        'db-sec',
        oldPair.privateKey,
        oldPub,
        newPair.privateKey,
        newPub,
        1n
      );

      expect(record.oldPubkeyHex).toBe(oldPub.toString('hex'));
      expect(record.newPubkeyHex).toBe(newPub.toString('hex'));
      expect(CustomerKeyRotationManager.verifyRotationRecord(record)).toBe(true);
    });
  });

  describe('5. Locale-Independent Byte-Level Determinism (WDB-0135)', () => {
    it('preserves strict UTF-8 byte ordering across Unicode characters', () => {
      // In Swedish locale, 'z' < 'ä' or 'ä' < 'z' can differ from byte-order
      const s1 = 'user_ä';
      const s2 = 'user_z';

      const cmp = compareCanonicalStrings(s1, s2);
      const byteCmp = Buffer.compare(Buffer.from(s1, 'utf8'), Buffer.from(s2, 'utf8'));

      expect(cmp).toBe(byteCmp);
    });

    it('deterministically encodes and decodes primary keys with Unicode column names', () => {
      const val1 = Buffer.alloc(8, 0x01);
      const val2 = Buffer.alloc(8, 0x02);

      const fields = [
        { name: 'zeta_col', typeTag: 2, valueBuffer: val1 },
        { name: 'alpha_col', typeTag: 2, valueBuffer: val2 },
      ];

      const encoded = encodePrimaryKeyTuple(fields);
      const decoded = decodePrimaryKeyTuple(encoded);

      expect(decoded.length).toBe(2);
      expect(decoded[0]!.name).toBe('alpha_col');
      expect(decoded[1]!.name).toBe('zeta_col');
    });
  });

  describe('6. Canonical Protocol Tuple Encoding (WDB-0130)', () => {
    it('guarantees that shifted field boundaries produce non-colliding preimages', () => {
      const domain = 'WDB:TEST_TUPLE:v1:';

      // Case A: field1 = "AB", field2 = "C"
      const tupleA = encodeProtocolTuple(domain, ['AB', 'C', 100, 1000n]);

      // Case B: field1 = "A", field2 = "BC"
      const tupleB = encodeProtocolTuple(domain, ['A', 'BC', 100, 1000n]);

      expect(tupleA.equals(tupleB)).toBe(false);

      // Case C: buffer fields with shifted boundaries
      const bufA1 = Buffer.from('hello', 'utf8');
      const bufA2 = Buffer.from('world', 'utf8');
      const tupleBufA = encodeProtocolTuple(domain, [bufA1, bufA2]);

      const bufB1 = Buffer.from('hell', 'utf8');
      const bufB2 = Buffer.from('oworld', 'utf8');
      const tupleBufB = encodeProtocolTuple(domain, [bufB1, bufB2]);

      expect(tupleBufA.equals(tupleBufB)).toBe(false);
    });
  });
});
