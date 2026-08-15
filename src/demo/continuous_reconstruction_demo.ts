import crypto from 'node:crypto';
import {
  WORMCheckpointStore,
  EvmAnchorAdapter,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  BaselineTracker,
  ContinuousStateReconstructionEngine,
  ContinuousReconstructionCli,
} from '../index.js';
import { MutationOperation, ChangeRecordData } from '../protocol/types.js';

export async function runContinuousReconstructionDemo(): Promise<void> {
  console.log('\n================================================================================');
  console.log('   WolverineDB v0.7.0: CONTINUOUS VERIFIED STATE RECONSTRUCTION DEMO            ');
  console.log('================================================================================\n');

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

  const approverKeys = [
    (() => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      return { publicKey: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32), privateKey };
    })(),
    (() => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      return { publicKey: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32), privateKey };
    })(),
  ];

  console.log('[1/5] Initializing Base Checkpoint #100...');
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

  await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, baseCheckpoint);
  const baseDigest = computeCheckpointDigest(baseCheckpoint);
  await evmAdapter.anchorCheckpoint(baseCheckpoint.checkpointId, baseDigest, baseCheckpoint.commitSeq);
  console.log(`      -> Base Checkpoint Anchored: ${baseDigest.toString('hex').slice(0, 24)}...`);

  console.log('\n[2/5] Simulating Interleaved Mutation History (Seq 101 .. 108)...');
  const pk1 = Buffer.from('00000001', 'hex');
  const pk2 = Buffer.from('00000002', 'hex');
  const pk3 = Buffer.from('00000003', 'hex');
  const pk4 = Buffer.from('00000004', 'hex');

  const changes = [
    {
      data: {
        formatVersion: 1,
        versionId: 'chg-101',
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
    {
      data: {
        formatVersion: 1,
        versionId: 'chg-102',
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
    {
      data: {
        formatVersion: 1,
        versionId: 'chg-103-malicious',
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
    {
      data: {
        formatVersion: 1,
        versionId: 'chg-104',
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
    {
      data: {
        formatVersion: 1,
        versionId: 'chg-105',
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
    {
      data: {
        formatVersion: 1,
        versionId: 'chg-106-malicious',
        transactionId: 'tx-106',
        timestampUs: 1723500600000000n,
        tableId: 'public.admin_secrets',
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
    {
      data: {
        formatVersion: 1,
        versionId: 'chg-107',
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
    {
      data: {
        formatVersion: 1,
        versionId: 'chg-108',
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
    tenantId: 'tenant-enterprise',
    baseCheckpoint,
    initialCheckpointState: new Map(),
    changesAfterCheckpoint: changes,
    externalVaultStore: vaultStore,
    evmAnchorAdapter: evmAdapter,
    baselineTracker,
    compromisedActors: ['attacker_compromised'],
    registeredScopes: ['public.users'],
    approverKeys,
  };

  console.log('\n[3/5] Computing Dual-Dimension Classification & Explanations...');
  const explainResult = await ContinuousReconstructionCli.executeReconstructExplain(workflowOptions);
  console.log(explainResult.output);

  console.log('\n[4/5] Evaluating Maximum Reconstructable State vs Contiguous Frontier...');
  const frontierResult = await ContinuousReconstructionCli.executeFrontier(workflowOptions);
  console.log(frontierResult.output);

  console.log('\n[5/5] Executing Continuous State Restoration & Emitting Certificate V2...');
  const { analysis, advisoryProposal } =
    await ContinuousStateReconstructionEngine.planContinuousReconstruction(workflowOptions);

  const { terminalOutput } =
    await ContinuousStateReconstructionEngine.executeContinuousRestoration(
      workflowOptions,
      analysis,
      advisoryProposal
    );

  console.log('\n' + terminalOutput);
  console.log('\nSUCCESS: Reconstructed maximum reconstructable state at Seq 108 without losing post-intrusion valid state!\n');
}
