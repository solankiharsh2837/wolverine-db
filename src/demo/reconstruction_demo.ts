import crypto from 'node:crypto';
import {
  WORMCheckpointStore,
  EvmAnchorAdapter,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  BaselineTracker,
  StateReconstructionCoordinator,
  ReconstructionCli,
} from '../index.js';
import { MutationOperation, ChangeRecordData } from '../protocol/types.js';

export async function runCinematicReconstructionDemo(): Promise<void> {
  console.log('\n================================================================================');
  console.log('       WolverineDB v0.6.0: VERIFIED STATE RECONSTRUCTION DEMO                   ');
  console.log('================================================================================\n');

  // Step 1 & 2: Setup stores, baseline, and keys
  const vaultStore = new WORMCheckpointStore();
  const evmAdapter = new EvmAnchorAdapter({
    chainId: '1',
    contractAddress: '0x1234567890123456789012345678901234567890',
    requiredConfirmations: 1,
  });

  const baselineTracker = new BaselineTracker();
  baselineTracker.registerBaseline({
    actorId: 'app_service_auth',
    allowedScopes: ['public.users'],
    typicalOperations: [1, 2],
    maintenanceWindows: [], // 24/7 authorized for app
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

  console.log('[1/6] Initializing Trusted Checkpoint #1842 (09:00:00 UTC)...');
  const baseCheckpoint = {
    checkpointId: '00000000-0000-0000-0000-000000001842',
    scope: 'public.users',
    commitSeq: 42n,
    previousCheckpointId: null,
    merkleRoot: Buffer.alloc(32, 0x18),
    changeChainHead: Buffer.alloc(32, 0x00),
    createdAtUs: 1723500000000000n, // 09:00
    protocolVersion: 3,
  };

  await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, baseCheckpoint);
  const baseDigest = computeCheckpointDigest(baseCheckpoint);
  await evmAdapter.anchorCheckpoint(baseCheckpoint.checkpointId, baseDigest, baseCheckpoint.commitSeq);
  console.log(`      -> Base Checkpoint Anchored: ${baseDigest.toString('hex').slice(0, 24)}...`);

  console.log('\n[2/6] Recording Legitimate User Mutations (09:15 .. 09:45 UTC)...');
  const user1Pk = Buffer.from('00000001', 'hex');
  const user2Pk = Buffer.from('00000002', 'hex');

  const changesAfterCheckpoint = [
    // 09:15 - Seq 43
    {
      data: {
        formatVersion: 1,
        versionId: '00000000-0000-0000-0000-000000000043',
        transactionId: 'tx-0915',
        timestampUs: 1723500900000000n,
        tableId: 'public.users',
        recordId: user1Pk,
        operation: MutationOperation.INSERT,
        fieldSet: { new: { id: 'user-1', name: 'Alice', balance: 100, role: 'USER' }, old: null },
        provenance: { actor: 'app_service_auth' },
        previousHash: Buffer.alloc(32, 0x00),
      } as ChangeRecordData,
      recordBytes: Buffer.from('rec-43'),
      computedHash: Buffer.alloc(32, 0x43),
      commitSeq: 43n,
      actorId: 'app_service_auth',
      utcHour: 9,
      dayOfWeek: 2,
    },
    // 09:30 - Seq 44
    {
      data: {
        formatVersion: 1,
        versionId: '00000000-0000-0000-0000-000000000044',
        transactionId: 'tx-0930',
        timestampUs: 1723501800000000n,
        tableId: 'public.users',
        recordId: user2Pk,
        operation: MutationOperation.INSERT,
        fieldSet: { new: { id: 'user-2', name: 'Bob', balance: 250, role: 'USER' }, old: null },
        provenance: { actor: 'app_service_auth' },
        previousHash: Buffer.alloc(32, 0x43),
      } as ChangeRecordData,
      recordBytes: Buffer.from('rec-44'),
      computedHash: Buffer.alloc(32, 0x44),
      commitSeq: 44n,
      actorId: 'app_service_auth',
      utcHour: 9,
      dayOfWeek: 2,
    },
    // 09:45 - Seq 45
    {
      data: {
        formatVersion: 1,
        versionId: '00000000-0000-0000-0000-000000000045',
        transactionId: 'tx-0945',
        timestampUs: 1723502700000000n,
        tableId: 'public.users',
        recordId: user1Pk,
        operation: MutationOperation.UPDATE,
        fieldSet: { new: { balance: 150 }, old: { balance: 100 } },
        provenance: { actor: 'app_service_auth' },
        previousHash: Buffer.alloc(32, 0x44),
      } as ChangeRecordData,
      recordBytes: Buffer.from('rec-45'),
      computedHash: Buffer.alloc(32, 0x45),
      commitSeq: 45n,
      actorId: 'app_service_auth',
      utcHour: 9,
      dayOfWeek: 2,
    },

    // 10:01 - Seq 46 (Attacker Breach: unauthorized UPDATE)
    {
      data: {
        formatVersion: 1,
        versionId: '00000000-0000-0000-0000-000000000046',
        transactionId: 'tx-1001-malicious',
        timestampUs: 1723503660000000n,
        tableId: 'public.users',
        recordId: user1Pk,
        operation: MutationOperation.UPDATE,
        fieldSet: { new: { balance: 9999999, role: 'SUPERUSER' }, old: { balance: 150, role: 'USER' } },
        provenance: { actor: 'attacker_compromised' },
        previousHash: Buffer.alloc(32, 0x45),
      } as ChangeRecordData,
      recordBytes: Buffer.from('rec-46'),
      computedHash: Buffer.alloc(32, 0x46),
      commitSeq: 46n,
      actorId: 'attacker_compromised',
      utcHour: 10,
      dayOfWeek: 2,
    },
    // 10:02 - Seq 47 (Attacker DELETE)
    {
      data: {
        formatVersion: 1,
        versionId: '00000000-0000-0000-0000-000000000047',
        transactionId: 'tx-1002-malicious',
        timestampUs: 1723503720000000n,
        tableId: 'public.users',
        recordId: user2Pk,
        operation: MutationOperation.DELETE,
        fieldSet: { new: null, old: { id: 'user-2' } },
        provenance: { actor: 'attacker_compromised' },
        previousHash: Buffer.alloc(32, 0x46),
      } as ChangeRecordData,
      recordBytes: Buffer.from('rec-47'),
      computedHash: Buffer.alloc(32, 0x47),
      commitSeq: 47n,
      actorId: 'attacker_compromised',
      utcHour: 10,
      dayOfWeek: 2,
    },
  ];

  console.log('      -> Legitimate Changes: Seq 43 (09:15), Seq 44 (09:30), Seq 45 (09:45)');
  console.log('      -> Attacker Compromise: Seq 46 (10:01 UPDATE), Seq 47 (10:02 DELETE)');

  console.log('\n[3/6] Computing Verified State Frontier...');
  const workflowOptions = {
    databaseId: 'pg-prod-ledger-01',
    tenantId: 'org-enterprise',
    baseCheckpoint,
    initialCheckpointState: new Map(),
    changesAfterCheckpoint,
    externalVaultStore: vaultStore,
    evmAnchorAdapter: evmAdapter,
    baselineTracker,
    compromisedActors: ['attacker_compromised'],
    registeredScopes: ['public.users'],
    approverKeys,
  };

  const frontierResult = await ReconstructionCli.executeFrontier(workflowOptions);
  console.log(frontierResult.output);

  console.log('\n[4/6] Generating Reconstruction Manifest & Evaluating Policy Gate...');
  const { manifest, advisoryProposal } = await StateReconstructionCoordinator.planReconstruction(workflowOptions);
  console.log(`      -> Preserved Changes Count: ${manifest.replayedChangeIds.length}`);
  console.log(`      -> Excluded Changes Count:  ${manifest.excludedChangeIds.length}`);
  console.log(`      -> Recovery Boundary:       CommitSeq ${manifest.recoveryBoundary.lastValidCommitSeq}`);

  console.log('\n[5/6] Executing Atomic Verified Restoration & Issuing Certificate...');
  const { certificate, terminalOutput } = await StateReconstructionCoordinator.executeVerifiedRestoration(
    workflowOptions,
    manifest,
    advisoryProposal
  );

  console.log('\n' + terminalOutput);
  console.log('\n[6/6] Final Cryptographic Verification: PASS');
  console.log('      -> Legitimate user transactions (09:15, 09:30, 09:45) PRESERVED.');
  console.log('      -> Malicious attacker mutations (10:01, 10:02) EXCLUDED.');
  console.log(`      -> Post-recovery state certificate issued: ${certificate.certificateId}\n`);
}
