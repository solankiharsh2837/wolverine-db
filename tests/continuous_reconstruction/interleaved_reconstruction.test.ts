import { describe, it, expect } from 'vitest';
import {
  WORMCheckpointStore,
  EvmAnchorAdapter,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  BaselineTracker,
  ContinuousStateReconstructionEngine,
  ContinuousReconstructionCli,
} from '../../src/index.js';
import { MutationOperation, ChangeRecordData } from '../../src/protocol/types.js';

describe('Continuous Interleaved State Reconstruction (WDB-0070, WDB-0073)', () => {
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

  it('critical requirement: preserves 101, 102, 104, 105, 107, 108 while isolating 103 and 106', async () => {
    const { vaultStore, evmAdapter, baselineTracker } = await setupEnv();

    const pk1 = Buffer.from('00000001', 'hex');
    const pk2 = Buffer.from('00000002', 'hex');
    const pk3 = Buffer.from('00000003', 'hex');
    const pk4 = Buffer.from('00000004', 'hex');

    const changes = [
      // 101 legitimate
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-00000000-0000-0000-0000-000000000101',
          transactionId: 'tx-101',
          timestampUs: 1723500100000000n,
          tableId: 'public.users',
          recordId: pk1,
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
        isIndependentCommitment: true,
      },
      // 102 legitimate
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-00000000-0000-0000-0000-000000000102',
          transactionId: 'tx-102',
          timestampUs: 1723500200000000n,
          tableId: 'public.users',
          recordId: pk2,
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 2, name: 'Bob', balance: 200 }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x01),
        } as ChangeRecordData,
        recordBytes: Buffer.from('102'),
        computedHash: Buffer.alloc(32, 0x02),
        commitSeq: 102n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
        isIndependentCommitment: true,
      },
      // 103 malicious (compromised actor)
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-00000000-0000-0000-0000-000000000103',
          transactionId: 'tx-103',
          timestampUs: 1723500300000000n,
          tableId: 'public.users',
          recordId: pk1,
          operation: MutationOperation.UPDATE,
          fieldSet: { new: { balance: 999999 }, old: { balance: 100 } },
          provenance: { actor: 'attacker_compromised' },
          previousHash: Buffer.alloc(32, 0x02),
        } as ChangeRecordData,
        recordBytes: Buffer.from('103'),
        computedHash: Buffer.alloc(32, 0x03),
        commitSeq: 103n,
        actorId: 'attacker_compromised',
        utcHour: 9,
        dayOfWeek: 1,
      },
      // 104 legitimate
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-00000000-0000-0000-0000-000000000104',
          transactionId: 'tx-104',
          timestampUs: 1723500400000000n,
          tableId: 'public.users',
          recordId: pk3,
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 3, name: 'Charlie', balance: 300 }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x03),
        } as ChangeRecordData,
        recordBytes: Buffer.from('104'),
        computedHash: Buffer.alloc(32, 0x04),
        commitSeq: 104n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
        isIndependentCommitment: true,
      },
      // 105 legitimate
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-00000000-0000-0000-0000-000000000105',
          transactionId: 'tx-105',
          timestampUs: 1723500500000000n,
          tableId: 'public.users',
          recordId: pk2,
          operation: MutationOperation.UPDATE,
          fieldSet: { new: { balance: 250 }, old: { balance: 200 } },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x04),
        } as ChangeRecordData,
        recordBytes: Buffer.from('105'),
        computedHash: Buffer.alloc(32, 0x05),
        commitSeq: 105n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
        isIndependentCommitment: true,
      },
      // 106 malicious (unauthorized scope)
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-00000000-0000-0000-0000-000000000106',
          transactionId: 'tx-106',
          timestampUs: 1723500600000000n,
          tableId: 'public.admin_secrets', // Unauthorized scope
          recordId: pk1,
          operation: MutationOperation.INSERT,
          fieldSet: { new: { secret: 'leaked' }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x05),
        } as ChangeRecordData,
        recordBytes: Buffer.from('106'),
        computedHash: Buffer.alloc(32, 0x06),
        commitSeq: 106n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
      },
      // 107 legitimate
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-00000000-0000-0000-0000-000000000107',
          transactionId: 'tx-107',
          timestampUs: 1723500700000000n,
          tableId: 'public.users',
          recordId: pk4,
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 4, name: 'David', balance: 400 }, old: null },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x06),
        } as ChangeRecordData,
        recordBytes: Buffer.from('107'),
        computedHash: Buffer.alloc(32, 0x07),
        commitSeq: 107n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
        isIndependentCommitment: true,
      },
      // 108 legitimate
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-00000000-0000-0000-0000-000000000108',
          transactionId: 'tx-108',
          timestampUs: 1723500800000000n,
          tableId: 'public.users',
          recordId: pk4,
          operation: MutationOperation.UPDATE,
          fieldSet: { new: { balance: 450 }, old: { balance: 400 } },
          provenance: { actor: 'authorized_app' },
          previousHash: Buffer.alloc(32, 0x07),
        } as ChangeRecordData,
        recordBytes: Buffer.from('108'),
        computedHash: Buffer.alloc(32, 0x08),
        commitSeq: 108n,
        actorId: 'authorized_app',
        utcHour: 9,
        dayOfWeek: 1,
        isIndependentCommitment: true,
      },
    ];

    const workflowOptions = {
      databaseId: 'pg-prod-ledger-01',
      tenantId: 'tenant-1',
      baseCheckpoint,
      initialCheckpointState: new Map(),
      changesAfterCheckpoint: changes,
      externalVaultStore: vaultStore,
      evmAnchorAdapter: evmAdapter,
      baselineTracker,
      compromisedActors: ['attacker_compromised'],
      registeredScopes: ['public.users'],
    };

    const { analysis } = await ContinuousStateReconstructionEngine.planContinuousReconstruction(workflowOptions);

    const preserved = analysis.decisions.filter((d) => d.decision === 'PRESERVE').map((d) => d.commitSeq);
    const excluded = analysis.decisions.filter((d) => d.decision === 'EXCLUDE').map((d) => d.commitSeq);

    // Assert exact decisions:
    expect(preserved).toEqual([101n, 102n, 104n, 105n, 107n, 108n]);
    expect(excluded).toEqual([103n, 106n]);

    expect(analysis.contiguousVerifiedFrontierSeq).toBe(102n); // Continuous up to 102
    expect(analysis.maximumReconstructableCommitSeq).toBe(108n); // Reconstructs all the way to 108!

    // Verify CLI explanation
    const explainCliResult = await ContinuousReconstructionCli.executeReconstructExplain(workflowOptions);
    expect(explainCliResult.success).toBe(true);
    expect(explainCliResult.output).toContain('Seq 101');
    expect(explainCliResult.output).toContain('✓ PRESERVE');
    expect(explainCliResult.output).toContain('Seq 103');
    expect(explainCliResult.output).toContain('✗ EXCLUDE');
    expect(explainCliResult.output).toContain('COMPROMISED');
  });
});
