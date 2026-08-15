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

describe('Hostile Tampering & Adversarial Invariants (WDB-0062)', () => {
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
      requiresTicketProvenance: true, // Requires ticket!
    });

    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, baseCheckpoint);
    const digest = computeCheckpointDigest(baseCheckpoint);
    await evmAdapter.anchorCheckpoint(baseCheckpoint.checkpointId, digest, baseCheckpoint.commitSeq);

    return { vaultStore, evmAdapter, baselineTracker };
  };

  it('scenario 8: detects unauthorized scope expansion outside actor baseline permissions', async () => {
    const { vaultStore, evmAdapter, baselineTracker } = await setupEnv();

    const changes = [
      {
        data: {
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000011',
          transactionId: 'tx-11',
          timestampUs: 1723500100000000n,
          tableId: 'public.admin_credentials', // Scope violation!
          recordId: Buffer.from('01', 'hex'),
          operation: MutationOperation.INSERT,
          fieldSet: { new: { key: 'secret' }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x00),
        } as ChangeRecordData,
        recordBytes: Buffer.from('11'),
        computedHash: Buffer.alloc(32, 0x11),
        commitSeq: 11n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
        ticketId: 'CHG-100',
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
    expect(result.compromiseReason).toContain('UNAUTHORIZED_SCOPE_MUTATION');
  });

  it('scenario 9: halts frontier when high-privilege change lacks required ticket ID', async () => {
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
        commitSeq: 11n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
        // No ticketId!
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
    expect(result.compromiseReason).toContain('MISSING_PROVENANCE_TICKET');
  });

  it('scenario 5: halts frontier when changes are reordered by attacker', async () => {
    const { vaultStore, evmAdapter, baselineTracker } = await setupEnv();

    // Attacker submits seq 12 before seq 11
    const changes = [
      {
        data: {
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000012',
          transactionId: 'tx-12',
          timestampUs: 1723500200000000n,
          tableId: 'public.users',
          recordId: Buffer.from('02', 'hex'),
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 2 }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x11),
        } as ChangeRecordData,
        recordBytes: Buffer.from('12'),
        computedHash: Buffer.alloc(32, 0x12),
        commitSeq: 12n, // Out of order! Base was 10, expecting 11
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
        ticketId: 'CHG-100',
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
    expect(result.compromiseReason).toContain('SEQUENCE_GAP_OR_OUT_OF_ORDER');
  });
});
