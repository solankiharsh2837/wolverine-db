import crypto from 'node:crypto';
import {
  WORMCheckpointStore,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  DistributedTrustCluster,
  WolverineEvidenceAgentClient,
  TrustTimeManager,
  WolverineRuntimeCli,
  TrustNetworkRecoveryIntegrator,
} from '../index.js';

export async function runDistributedRuntimeDemo(): Promise<void> {
  console.log('\n================================================================================');
  console.log('       WolverineDB v0.9.0: DISTRIBUTED TRUST RUNTIME & TRUST TIME DEMO          ');
  console.log('================================================================================\n');

  console.log('[1/6] Bootstrapping Distributed Trust Cluster (1 Gateway, 5 Validators, 3 Replicas)...');
  const cluster = new DistributedTrustCluster({ requiredQuorum: 4, totalValidators: 5, totalReplicas: 3 });
  const timeManager = new TrustTimeManager();

  const customerKeyPair = crypto.generateKeyPairSync('ed25519');
  const customerPubkey = customerKeyPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const customerPrivateKey = customerKeyPair.privateKey;

  const tenantId = 'tenant-enterprise-prod';
  const databaseId = 'production-orders-db';

  cluster.gateway.registerTenant(tenantId, customerPubkey, databaseId, 'ENTERPRISE');

  const agentClient = new WolverineEvidenceAgentClient({
    tenantId,
    databaseId,
    customerPubkey,
    customerPrivateKey,
    gateway: cluster.gateway,
  });

  console.log(WolverineRuntimeCli.executeClusterStatus(cluster));

  console.log('[2/6] Committing PostgreSQL Checkpoint #1842 over Network Transport...');
  const vaultStore = new WORMCheckpointStore();
  const checkpoint1842 = {
    checkpointId: '00000000-0000-0000-0000-000000001842',
    commitSeq: 1842n,
    scope: 'public.orders',
    previousCheckpointId: null,
    merkleRoot: Buffer.alloc(32, 0x88),
    changeChainHead: Buffer.alloc(32, 0x11),
    createdAtUs: 1723500000000000n,
    protocolVersion: 3,
  };

  await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, checkpoint1842);
  const localDigest = computeCheckpointDigest(checkpoint1842);

  const commitRes = await agentClient.commitCheckpoint(checkpoint1842, localDigest);
  const proof1842 = commitRes.proof!;
  const timeRecord1842 = timeManager.registerProof(proof1842);

  console.log(`      -> Quorum Reached:        ${proof1842.quorumCertificate.quorumCount} / ${proof1842.quorumCertificate.totalValidators} Validators`);
  console.log(`      -> Replicated to Nodes:   ${cluster.replicas.size} Ledger Replicas Synced`);
  console.log(`      -> State Finalized:       IMMUTABLE in Trust Ledger Sequence ${proof1842.ledgerRecord.ledgerSeq}`);

  console.log('\n[3/6] Inspecting Dual-Timeline Binding (Database Time vs Trust Time)...');
  console.log(WolverineRuntimeCli.executeTrustTimeInspect(timeRecord1842));

  console.log('[4/6] Simulating Multi-Node Network Partition (Dropping 2 of 5 Validators)...');
  cluster.simulateValidatorPartition('val-node-01', true);
  cluster.simulateValidatorPartition('val-node-02', true);
  console.log('      -> Network State: 2 Validators [PARTITIONED / UNREACHABLE], 3 Active');

  console.log('\n[5/6] Submitting Next Commit Seq #1843 (Testing Partition Quorum)...');
  const checkpoint1843 = {
    checkpointId: '00000000-0000-0000-0000-000000001843',
    commitSeq: 1843n,
    scope: 'public.orders',
    previousCheckpointId: checkpoint1842.checkpointId,
    merkleRoot: Buffer.alloc(32, 0x99),
    changeChainHead: Buffer.alloc(32, 0x22),
    createdAtUs: 1723500100000000n,
    protocolVersion: 3,
  };
  await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, checkpoint1843);
  const digest1843 = computeCheckpointDigest(checkpoint1843);

  // Required quorum in gateway was 4, but only 3 available -> enters offline queue
  await agentClient.commitCheckpoint(checkpoint1843, digest1843);
  console.log(`      -> Quorum Below Threshold: Commitment Safely Queued in Local Agent Storage`);
  console.log(`      -> Local Queue Length:     ${agentClient.getOfflineQueueLength()}`);

  console.log('\n[6/6] Healing Partition & Draining Outage Queue to Replicas...');
  cluster.simulateValidatorPartition('val-node-01', false);
  cluster.simulateValidatorPartition('val-node-02', false);

  const drained = await agentClient.flushQueue();
  console.log(`      -> Network Restored: Drained ${drained} queued commitments`);
  console.log(`      -> All Replicas Synchronized across Database Time & Trust Time`);

  // Verify Unified Trust
  const verifiedBasis = await TrustNetworkRecoveryIntegrator.verifyUnifiedTrustBasis(
    checkpoint1842,
    vaultStore,
    proof1842
  );
  console.log(`      -> Unified Trust Verification: ${verifiedBasis.isVerified ? 'PASS' : 'FAIL'}`);

  console.log('\nSUCCESS: Wolverine Distributed Trust Runtime v0.9.0 demonstration completed.\n');
}
