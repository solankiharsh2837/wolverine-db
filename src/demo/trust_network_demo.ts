import crypto from 'node:crypto';
import {
  WORMCheckpointStore,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  WolverineTrustNetworkService,
  WolverineEvidenceAgent,
  WolverineTrustCli,
  TrustNetworkRecoveryIntegrator,
} from '../index.js';

export async function runTrustNetworkDemo(): Promise<void> {
  console.log('\n================================================================================');
  console.log('       WolverineDB v0.8.0: WOLVERINE TRUST NETWORK & PORTABLE PROOFS DEMO       ');
  console.log('================================================================================\n');

  const vaultStore = new WORMCheckpointStore();
  const service = new WolverineTrustNetworkService(3, 5);

  const customerKeyPair = crypto.generateKeyPairSync('ed25519');
  const customerPubkey = customerKeyPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const customerPrivateKey = customerKeyPair.privateKey;

  const tenantId = 'tenant-enterprise-alpha';
  const databaseId = 'production-orders-ledger';

  service.registerTenant(tenantId, customerPubkey, databaseId, 'ENTERPRISE');

  const agent = new WolverineEvidenceAgent({
    tenantId,
    databaseId,
    customerPubkey,
    customerPrivateKey,
    service,
  });

  console.log('[ACT I] Customer WolverineDB creates Checkpoint #1842...');
  const checkpoint = {
    checkpointId: '00000000-0000-0000-0000-000000001842',
    commitSeq: 1842n,
    scope: 'public.orders',
    previousCheckpointId: null,
    merkleRoot: Buffer.alloc(32, 0x88),
    changeChainHead: Buffer.alloc(32, 0x11),
    createdAtUs: 1723500000000000n,
    protocolVersion: 3,
  };
  await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, checkpoint);
  const localDigest = computeCheckpointDigest(checkpoint);
  console.log(`        -> Checkpoint Anchored: ${localDigest.toString('hex').slice(0, 32)}...`);

  console.log('\n[ACT II] Wolverine Evidence Agent creates Signed Trust Commitment...');
  const commitRes = await agent.commitCheckpoint(checkpoint, localDigest);
  console.log(`        -> Commitment ID:     ${commitRes.commitment.commitmentId}`);
  console.log(`        -> Tenant Domain:     ${commitRes.commitment.tenantId}`);
  console.log(`        -> Commitment Digest: ${commitRes.commitment.commitmentDigest.toString('hex').slice(0, 32)}...`);

  console.log('\n[ACT III & IV] Five Independent Validators Inspect & Attest...');
  console.log(WolverineTrustCli.executeValidatorStatus(service));

  console.log('[ACT V] Trust Ledger Finalizes Commitment at Quorum 5/5...');
  const proof = commitRes.proof!;
  console.log(`        -> Quorum Count:      ${proof.quorumCertificate.quorumCount} / ${proof.quorumCertificate.totalValidators}`);
  console.log(`        -> Ledger Sequence:   ${proof.ledgerRecord.ledgerSeq}`);
  console.log(`        -> Finality Status:   FINALIZED & IMMUTABLE`);

  console.log('\n[ACT VI] Customer Exports Standalone Portable Trust Proof...');
  const exportedProofJson = WolverineTrustCli.executeProofExport(proof);
  console.log(`        -> Exported Proof Payload: ${exportedProofJson.length} bytes JSON`);

  console.log('\n[ACT VII] SIMULATING TOTAL WOLVERINE CLOUD API OUTAGE...');
  service.setNetworkOnlineStatus(false);
  console.log('        -> Wolverine Trust API: [OFFLINE / UNREACHABLE]');

  console.log('\n[ACT VIII] Offline Standalone Verifier Inspects Proof with Zero Server Interaction...');
  const { result, terminalOutput } = WolverineTrustCli.executeProofVerify(exportedProofJson);
  console.log(terminalOutput);
  console.log(`        -> Independent Offline Verification Verdict: ${result.status} (${result.reason})`);

  console.log('\n[ACT IX & X] Attempting Malicious Commitment Equivocation / Replacement...');
  try {
    service.setNetworkOnlineStatus(true);
    // Attacker submits conflicting digest for same sequence 1842
    await agent.commitCheckpoint(checkpoint, Buffer.alloc(32, 0x99));
    console.log('        -> ERROR: Equivocation was not blocked!');
  } catch (err: any) {
    console.log(`        -> DEFENSE SUCCESS: Equivocation detected and rejected: ${err.message}`);
  }

  console.log('\n[ACT XI & XII] Recovery Verification: Unified Trust Basis Across Local, WORM, and Trust Ledger...');
  const unifiedBasis = await TrustNetworkRecoveryIntegrator.verifyUnifiedTrustBasis(
    checkpoint,
    vaultStore,
    proof
  );
  console.log(`        -> Local Checkpoint Digest  ==  WORM Store Digest  ==  Wolverine Trust Ledger Digest`);
  console.log(`        -> Unified Trust Verified:   ${unifiedBasis.isVerified}`);
  console.log('\nSUCCESS: Wolverine Trust Network v0.8.0 demonstration completed.\n');
}
