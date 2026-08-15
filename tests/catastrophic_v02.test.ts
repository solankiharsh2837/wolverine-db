import { describe, it, expect } from 'vitest';
import { CheckpointAnchorEngine } from '../src/checkpoint/anchor.js';
import { WORMCheckpointStore } from '../src/checkpoint/worm.js';
import { MerkleTree } from '../src/crypto/merkle.js';
import { verifyChangeHashChain, StoredChangeRecord } from '../src/engine/verifier.js';
import { computeChangeHash, GENESIS_PREDECEASED_HASH } from '../src/crypto/hash.js';

describe('v0.2 Catastrophic Hardening & Split-Brain Detection', () => {
  it('property: detects Split-Brain divergence when PostgreSQL is tampered but external anchor is intact', async () => {
    const store = new WORMCheckpointStore();

    // 1. Legitimate state before attack
    const honestLeaves = [Buffer.from('account:alice:$1000'), Buffer.from('account:bob:$500')];
    const honestTree = new MerkleTree(honestLeaves);
    const honestRoot = honestTree.root;

    // 2. Anchor legitimate checkpoint externally
    const checkpointId = '00000000-0000-0000-0000-000000000042';
    await CheckpointAnchorEngine.anchorCheckpoint(store, {
      checkpointId,
      scope: 'public.accounts',
      commitSeq: 42n,
      previousCheckpointId: '00000000-0000-0000-0000-000000000041',
      merkleRoot: honestRoot,
      changeChainHead: Buffer.alloc(32, 0x42),
      createdAtUs: 1723500000000000n,
      protocolVersion: 2,
    });

    // 3. Compromised DBA bypasses Wolverine and modifies Postgres directly
    const maliciousLeaves = [Buffer.from('account:alice:$1000'), Buffer.from('account:bob:$9999999')]; // Tampered
    const maliciousTree = new MerkleTree(maliciousLeaves);
    const observedLocalRoot = maliciousTree.root;

    // 4. Wolverine runs split-brain verification
    const verification = await CheckpointAnchorEngine.verifyAgainstExternalAnchor(
      store,
      checkpointId,
      observedLocalRoot
    );

    expect(verification.status).toBe('STATE_DIVERGENCE_DETECTED');
    expect(verification.externalAnchorValid).toBe(true);
    expect(verification.expectedRoot).toBe(honestRoot.toString('hex'));
    expect(verification.localRoot).toBe(observedLocalRoot.toString('hex'));
    expect(verification.errorMessage).toContain('PostgreSQL state has diverged');
  });

  it('property: catastrophic scenario - reconstructs provable prefix, strictly refuses unprovable tampered suffix', () => {
    // 1. Build 10 valid change records
    const records: StoredChangeRecord[] = [];
    let prevHash = GENESIS_PREDECEASED_HASH;

    for (let i = 1; i <= 10; i++) {
      const payload = Buffer.from(`change_${i}`);
      // Tagged binary structure
      const recordBytes = Buffer.concat([
        Buffer.from([0x57, 0x44, 0x42, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01]),
        Buffer.from([0x00, 0x01, 0x05, 0x00, 0x00, 0x00, payload.length]),
        payload,
      ]);
      const changeHash = computeChangeHash(recordBytes, prevHash);
      records.push({
        changeSeq: i,
        changeHash,
        previousHash: prevHash,
        recordBytes,
      });
      prevHash = changeHash;
    }

    // 2. Attacker corrupts change_seq 7 onwards in Postgres
    records[6].recordBytes = Buffer.from('corrupted_payload_by_dba');

    // 3. Verifier checks chain
    const report = verifyChangeHashChain(records);

    // Verifier MUST prove records 1..6 and refuse records 7..10
    expect(report.status).toBe('MALFORMED_RECORD');
    expect(report.checkedRecordsCount).toBe(6); // 6 proven records
    expect(report.firstFailureSeq).toBe(7);
  });
});
