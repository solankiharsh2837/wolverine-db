import { describe, it, expect } from 'vitest';
import {
  WORMCheckpointStore,
  EvmAnchorAdapter,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  BaselineTracker,
  ContinuousHistoryClassifier,
} from '../../src/index.js';
import { MutationOperation, ChangeRecordData } from '../../src/protocol/types.js';

describe('Dependency Graph Safety & Conflict Handling (WDB-0072, WDB-0074)', () => {
  const baseCheckpoint = {
    checkpointId: '00000000-0000-0000-0000-000000000100',
    scope: 'public.users',
    commitSeq: 100n,
    previousCheckpointId: null,
    merkleRoot: Buffer.alloc(32, 0x10),
    changeChainHead: Buffer.alloc(32, 0x00),
    createdAtUs: 1723500000000000n,
    protocolVersion: 3,
  };

  const setupEnv = async () => {
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });
    const baselineTracker = new BaselineTracker();
    baselineTracker.registerBaseline({
      actorId: 'authorized_app',
      allowedScopes: ['public.users'],
      typicalOperations: [1, 2, 3],
      maintenanceWindows: [],
      maxMutationsPerMinute: 100,
      averageBatchSize: 5,
      requiresTicketProvenance: false,
    });

    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, baseCheckpoint);
    const digest = computeCheckpointDigest(baseCheckpoint);
    await evmAdapter.anchorCheckpoint(baseCheckpoint.checkpointId, digest, baseCheckpoint.commitSeq);

    return { vaultStore, evmAdapter, baselineTracker };
  };

  it('case B: blocks legitimate mutation when it depends on an excluded malicious mutation', async () => {
    const { baselineTracker } = await setupEnv();

    const userPk = Buffer.from('00000001', 'hex');

    const changes = [
      // 101 legitimate INSERT
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-101',
          transactionId: 'tx-101',
          timestampUs: 1723500100000000n,
          tableId: 'public.users',
          recordId: userPk,
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 1, name: 'Alice', balance: 100 }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x00),
        } as ChangeRecordData,
        recordBytes: Buffer.from('101'),
        computedHash: Buffer.alloc(32, 0x01),
        commitSeq: 101n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
      },
      // 102 malicious DELETE of Alice
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-102',
          transactionId: 'tx-102',
          timestampUs: 1723500200000000n,
          tableId: 'public.users',
          recordId: userPk,
          operation: MutationOperation.DELETE,
          fieldSet: { new: null, old: { id: 1 } },
          provenance: { actor: 'attacker_compromised' },
          previousHash: Buffer.alloc(32, 0x01),
        } as ChangeRecordData,
        recordBytes: Buffer.from('102'),
        computedHash: Buffer.alloc(32, 0x02),
        commitSeq: 102n,
        actorId: 'attacker_compromised',
        utcHour: 9,
        dayOfWeek: 1,
      },
      // 103 legitimate UPDATE that depended on 102's state (which was excluded)
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-103',
          transactionId: 'tx-103',
          timestampUs: 1723500300000000n,
          tableId: 'public.users',
          recordId: userPk,
          operation: MutationOperation.UPDATE,
          fieldSet: { new: { balance: 200 }, old: { balance: 100 } },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x02),
        } as ChangeRecordData,
        recordBytes: Buffer.from('103'),
        computedHash: Buffer.alloc(32, 0x03),
        commitSeq: 103n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
        isIndependentCommitment: true,
      },
    ];

    const analysis = ContinuousHistoryClassifier.analyzeHistory({
      baseCheckpoint,
      initialCheckpointState: new Map(),
      changesAfterCheckpoint: changes,
      baselineTracker,
      compromisedActors: ['attacker_compromised'],
    });

    const d101 = analysis.decisions.find((d) => d.commitSeq === 101n);
    const d102 = analysis.decisions.find((d) => d.commitSeq === 102n);
    const d103 = analysis.decisions.find((d) => d.commitSeq === 103n);

    expect(d101?.decision).toBe('PRESERVE');
    expect(d102?.decision).toBe('EXCLUDE');
    expect(d103?.decision).toBe('BLOCK');
    expect(d103?.classification).toBe('DEPENDENCY_BLOCKED');
  });

  it('case D: detects state conflict when two competing mutations collide on the same row version', async () => {
    const { baselineTracker } = await setupEnv();

    const userPk = Buffer.from('00000001', 'hex');

    const changes = [
      // 101 legitimate INSERT
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-101',
          transactionId: 'tx-101',
          timestampUs: 1723500100000000n,
          tableId: 'public.users',
          recordId: userPk,
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 1, name: 'Alice' }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x00),
        } as ChangeRecordData,
        recordBytes: Buffer.from('101'),
        computedHash: Buffer.alloc(32, 0x01),
        commitSeq: 101n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
      },
      // 102 second INSERT with identical PK (collision/conflict)
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-102',
          transactionId: 'tx-102',
          timestampUs: 1723500200000000n,
          tableId: 'public.users',
          recordId: userPk,
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 1, name: 'Alice Clone' }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x01),
        } as ChangeRecordData,
        recordBytes: Buffer.from('102'),
        computedHash: Buffer.alloc(32, 0x02),
        commitSeq: 102n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
      },
    ];

    const analysis = ContinuousHistoryClassifier.analyzeHistory({
      baseCheckpoint,
      initialCheckpointState: new Map(),
      changesAfterCheckpoint: changes,
      baselineTracker,
    });

    const d102 = analysis.decisions.find((d) => d.commitSeq === 102n);
    expect(d102?.decision).toBe('CONFLICT');
    expect(d102?.classification).toBe('STATE_CONFLICT');
  });
});
