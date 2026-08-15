import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WORMCheckpointStore,
  EvmAnchorAdapter,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  BaselineTracker,
  ContinuousStateReconstructionEngine,
  DistributedTrustCluster,
  WolverineEvidenceAgentClient,
  TrustNetworkRecoveryIntegrator,
  TrustTimeManager,
} from '../../src/index.js';
import { MutationOperation, ChangeRecordData } from '../../src/protocol/types.js';

describe('End-to-End PostgreSQL & Trust Time Reconstruction Pipeline (WDB-0070..0076, WDB-0090..0095)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('end-to-end: verifies checkpoint in Trust Time, isolates malicious transactions, reconstructs state, and re-anchors to Trust Network', async () => {
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });
    const cluster = new DistributedTrustCluster({ requiredQuorum: 3, totalValidators: 5 });
    const timeManager = new TrustTimeManager();

    const customer = genKeys();
    cluster.gateway.registerTenant('tenant-enterprise-e2e', customer.pub, 'public.users');

    const agentClient = new WolverineEvidenceAgentClient({
      tenantId: 'tenant-enterprise-e2e',
      databaseId: 'public.users',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      gateway: cluster.gateway,
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

    // [1] Establish Base Checkpoint 100 in Trust Time
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

    const baseCommitRes = await agentClient.commitCheckpoint(baseCheckpoint, baseDigest);
    const baseProof = baseCommitRes.proof!;
    timeManager.registerProof(baseProof);

    // [2] Verify Unified Trust Basis
    const unifiedBasis = await TrustNetworkRecoveryIntegrator.verifyUnifiedTrustBasis(
      baseCheckpoint,
      vaultStore,
      baseProof
    );
    expect(unifiedBasis.isVerified).toBe(true);

    // [3] Simulate Interleaved Mutations (Seq 101 .. 108) with Attacker Injections
    const pk1 = Buffer.from('00000001', 'hex');
    const pk2 = Buffer.from('00000002', 'hex');

    const changes = [
      // 101 Legit
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
      },
      // 102 Malicious (Compromised DBA)
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-102',
          transactionId: 'tx-102',
          timestampUs: 1723500200000000n,
          tableId: 'public.users',
          recordId: pk1,
          operation: MutationOperation.UPDATE,
          fieldSet: { new: { balance: 999999 }, old: { balance: 100 } },
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
      // 103 Legit (Independent Row PK2)
      {
        data: {
          formatVersion: 1,
          versionId: 'chg-103',
          transactionId: 'tx-103',
          timestampUs: 1723500300000000n,
          tableId: 'public.users',
          recordId: pk2,
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 2, name: 'Bob', balance: 200 }, old: null },
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

    const workflowOptions = {
      databaseId: 'public.users',
      tenantId: 'tenant-enterprise-e2e',
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

    // [4] Plan and Execute Continuous Reconstruction
    const { analysis, advisoryProposal } =
      await ContinuousStateReconstructionEngine.planContinuousReconstruction(workflowOptions);

    const { certificateV2, newCheckpoint } =
      await ContinuousStateReconstructionEngine.executeContinuousRestoration(
        workflowOptions,
        analysis,
        advisoryProposal
      );

    expect(certificateV2.policyApprovalStatus).toBe('PASS');
    expect(analysis.maximumReconstructableCommitSeq).toBe(103n);
    expect(certificateV2.preservedMutationIds).toEqual(['chg-101', 'chg-103']);
    expect(certificateV2.excludedMutationIds).toEqual(['chg-102']);

    // [5] Re-Anchor Post-Recovery Checkpoint to Distributed Trust Network
    const postRecoveryDigest = computeCheckpointDigest(newCheckpoint);
    const postRecoveryRes = await agentClient.commitCheckpoint(newCheckpoint, postRecoveryDigest);
    expect(postRecoveryRes.isSynchronized).toBe(true);

    const postProof = postRecoveryRes.proof!;
    timeManager.registerProof(postProof);

    expect(postProof.quorumCertificate.quorumCount).toBeGreaterThanOrEqual(3);
    expect(postProof.ledgerRecord.ledgerSeq).toBe('2'); // Advanced in Trust Time!
  });
});
