import { describe, it, expect } from 'vitest';
import {
  WORMCheckpointStore,
  EvmAnchorAdapter,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  BaselineTracker,
  VerifiedStateFrontierEngine,
} from '../../src/index.js';
import { MutationOperation, ChangeRecordData } from '../../src/protocol/types.js';

describe('Verified State Frontier (WDB-0060 Hostile Hardening)', () => {
  const baseCheckpoint = {
    checkpointId: '00000000-0000-0000-0000-000000001842',
    scope: 'public.users',
    commitSeq: 10n,
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
      typicalOperations: [1, 2],
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

  it('scenario 1 & 18: preserves multiple legitimate changes before compromise', async () => {
    const { vaultStore, evmAdapter, baselineTracker } = await setupEnv();

    const changes = [
      {
        data: {
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000011',
          transactionId: 'tx-11',
          timestampUs: 1723500100000000n,
          tableId: 'public.users',
          recordId: Buffer.from('01', 'hex'),
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 1, name: 'Alice' }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x00),
        } as ChangeRecordData,
        recordBytes: Buffer.from('11'),
        computedHash: Buffer.alloc(32, 0x11),
        commitSeq: 11n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
      },
      {
        data: {
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000012',
          transactionId: 'tx-12',
          timestampUs: 1723500200000000n,
          tableId: 'public.users',
          recordId: Buffer.from('02', 'hex'),
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 2, name: 'Bob' }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x11),
        } as ChangeRecordData,
        recordBytes: Buffer.from('12'),
        computedHash: Buffer.alloc(32, 0x12),
        commitSeq: 12n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
      },
      // Compromised change
      {
        data: {
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000013',
          transactionId: 'tx-13',
          timestampUs: 1723500300000000n,
          tableId: 'public.users',
          recordId: Buffer.from('01', 'hex'),
          operation: MutationOperation.UPDATE,
          fieldSet: { new: { role: 'SUPERUSER' }, old: { role: 'USER' } },
          provenance: { actor: 'compromised_actor' },
          previousHash: Buffer.alloc(32, 0x12),
        } as ChangeRecordData,
        recordBytes: Buffer.from('13'),
        computedHash: Buffer.alloc(32, 0x13),
        commitSeq: 13n,
        actorId: 'compromised_actor',
        utcHour: 9,
        dayOfWeek: 1,
      },
    ];

    const result = await VerifiedStateFrontierEngine.calculateFrontier({
      baseCheckpoint,
      changesAfterCheckpoint: changes,
      externalVaultStore: vaultStore,
      evmAnchorAdapter: evmAdapter,
      baselineTracker,
      compromisedActors: ['compromised_actor'],
    });

    expect(result.isFrontierValid).toBe(true);
    expect(result.frontierCommitSeq).toBe(12n);
    expect(result.preservedChanges).toHaveLength(2);
    expect(result.excludedChanges).toHaveLength(1);
    expect(result.firstInvalidCommitSeq).toBe(13n);
  });

  it('scenario 10: halts frontier when commit sequence is missing/discontinuous', async () => {
    const { vaultStore, evmAdapter, baselineTracker } = await setupEnv();

    const changes = [
      {
        data: {
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000011',
          transactionId: 'tx-11',
          timestampUs: 1723500100000000n,
          tableId: 'public.users',
          recordId: Buffer.from('01', 'hex'),
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 1 }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x00),
        } as ChangeRecordData,
        recordBytes: Buffer.from('11'),
        computedHash: Buffer.alloc(32, 0x11),
        commitSeq: 13n, // Skipped seq 11 and 12! Expected 11
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
      },
    ];

    const result = await VerifiedStateFrontierEngine.calculateFrontier({
      baseCheckpoint,
      changesAfterCheckpoint: changes,
      externalVaultStore: vaultStore,
      evmAnchorAdapter: evmAdapter,
      baselineTracker,
    });

    expect(result.frontierCommitSeq).toBe(10n); // Remains at base checkpoint
    expect(result.preservedChanges).toHaveLength(0);
    expect(result.excludedChanges).toHaveLength(1);
    expect(result.compromiseReason).toContain('SEQUENCE_GAP_OR_OUT_OF_ORDER');
  });

  it('scenario 11: halts frontier when previous hash chain link is broken', async () => {
    const { vaultStore, evmAdapter, baselineTracker } = await setupEnv();

    const changes = [
      {
        data: {
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000011',
          transactionId: 'tx-11',
          timestampUs: 1723500100000000n,
          tableId: 'public.users',
          recordId: Buffer.from('01', 'hex'),
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 1 }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0xde), // Broken previous hash!
        } as ChangeRecordData,
        recordBytes: Buffer.from('11'),
        computedHash: Buffer.alloc(32, 0x11),
        commitSeq: 11n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
      },
    ];

    const result = await VerifiedStateFrontierEngine.calculateFrontier({
      baseCheckpoint,
      changesAfterCheckpoint: changes,
      externalVaultStore: vaultStore,
      evmAnchorAdapter: evmAdapter,
      baselineTracker,
    });

    expect(result.frontierCommitSeq).toBe(10n);
    expect(result.preservedChanges).toHaveLength(0);
    expect(result.compromiseReason).toContain('HASH_CHAIN_DISCONTINUITY');
  });

  it('scenario 17: supports recovery exactly at checkpoint boundary (zero changes after checkpoint)', async () => {
    const { vaultStore, evmAdapter, baselineTracker } = await setupEnv();

    const result = await VerifiedStateFrontierEngine.calculateFrontier({
      baseCheckpoint,
      changesAfterCheckpoint: [],
      externalVaultStore: vaultStore,
      evmAnchorAdapter: evmAdapter,
      baselineTracker,
    });

    expect(result.isFrontierValid).toBe(true);
    expect(result.frontierCommitSeq).toBe(10n);
    expect(result.preservedChanges).toHaveLength(0);
    expect(result.excludedChanges).toHaveLength(0);
  });
});
