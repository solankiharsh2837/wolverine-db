import crypto from 'node:crypto';
import pg from 'pg';
import { BesuClient } from '../blockchain/besu/client.js';
import { deployTrustRegistry } from '../blockchain/besu/deploy.js';
import { BesuRpcPool } from '../blockchain/besu/rpc_pool.js';
import { DeterministicStateFrontier } from '../evidence/state_frontier.js';
import { DurableEvidenceJournal } from '../evidence/journal.js';
import { PgLogicalClient } from '../wal/pg_logical_client.js';
import {
  CanonicalTrustCommitmentV3,
  computeCanonicalCommitmentDigest,
  computeAgentAttestPreimage,
  formatHex16,
  formatHex32,
} from '../protocol/commitment_v3.js';
import { Secp256k1CustomerSigningProvider } from '../crypto/secp256k1_provider.js';
import { UniversalTrustReceiptGenerator, UniversalTrustReceipt } from '../receipts/universal_receipt.js';
import { UniversalReceiptVerifier } from '../proof/universal_receipt_verifier.js';

export interface AcceptanceConfig {
  postgresUrl: string;
  besuRpcUrls: string[];
  chainId: number;
  operatorPrivateKey: `0x${string}`;
}

const DEFAULT_CONFIG: AcceptanceConfig = {
  postgresUrl: process.env.DATABASE_URL || 'postgresql://wdb_user:wdb_password@127.0.0.1:5434/wolverine_prod',
  besuRpcUrls: [
    'http://127.0.0.1:8545',
    'http://127.0.0.1:8546',
    'http://127.0.0.1:8547',
    'http://127.0.0.1:8548',
    'http://127.0.0.1:8549',
  ],
  chainId: 13370,
  operatorPrivateKey: '0x0000000000000000000000000000000000000000000000000000000000000001',
};

export async function runLiveAcceptanceSuite(config: AcceptanceConfig = DEFAULT_CONFIG): Promise<boolean> {
  console.log('\n========================================================================');
  console.log('  WOLVERINEDB — LIVE TRUST-PLANE ACCEPTANCE SUITE (CANONICAL V3)');
  console.log('========================================================================');

  const tenantId = `tenant_${Date.now()}`;
  const databaseId = 'postgres_main';

  // Customer Sovereign Key (SECP256k1 EIP-712)
  const customerSigner = new Secp256k1CustomerSigningProvider();
  const customerSigningAddress = customerSigner.getAddress();

  // STAGE 1: Hyperledger Besu QBFT Cluster Health
  console.log('\n[STAGE 1] Validating Hyperledger Besu QBFT Cluster Health...');
  const rpcPool = new BesuRpcPool({
    nodes: config.besuRpcUrls,
    chainId: config.chainId,
    timeoutMs: 4000,
  });

  const statuses = await rpcPool.probeAllNodes();
  const healthyCount = statuses.filter((s) => s.isHealthy).length;
  console.log(`  Healthy Besu Nodes: ${healthyCount} / ${config.besuRpcUrls.length}`);
  if (healthyCount < 4) {
    throw new Error(`Insufficient healthy Besu validators: ${healthyCount} (minimum 4 required)`);
  }

  // STAGE 2: Smart Contract Deployment / Hardened Registry
  console.log('\n[STAGE 2] Deploying Hardened WolverineTrustRegistry.sol...');
  const deployRes = await deployTrustRegistry(config.besuRpcUrls[0]!);
  console.log(`  Contract Address: ${deployRes.contractAddress}`);
  console.log(`  Deployment Tx:    ${deployRes.deploymentTxHash}`);

  const besuClient = new BesuClient({
    rpcUrl: config.besuRpcUrls[0]!,
    chainId: config.chainId,
    contractAddress: deployRes.contractAddress,
    operatorPrivateKeyHex: config.operatorPrivateKey,
  });

  // STAGE 3: Sovereign Tenant Onboarding On-Chain
  console.log('\n[STAGE 3] Registering Sovereign Tenant On-Chain...');
  const regTx = await besuClient.registerTenant(
    tenantId,
    customerSigningAddress,
    '0xfe3b557e8fb62b89f4916b721be55ceb828dbd73' // Deployer / Authorized Gateway Address
  );
  console.log(`  Tenant Registered: ${tenantId}`);
  console.log(`  Customer Signer:   ${customerSigningAddress}`);
  console.log(`  Registration Tx:   ${regTx.txHash}`);

  // STAGE 4: PostgreSQL Setup & Bootstrap
  console.log('\n[STAGE 4] Initializing PostgreSQL Baseline...');
  const pgClient = new pg.Client({ connectionString: config.postgresUrl });
  await pgClient.connect();

  await pgClient.query(`
    DROP TABLE IF EXISTS public.accounts CASCADE;
    CREATE TABLE public.accounts (
      id TEXT PRIMARY KEY,
      balance NUMERIC NOT NULL,
      owner TEXT NOT NULL
    );
    INSERT INTO public.accounts (id, balance, owner) VALUES
      ('acc_001', 50000.00, 'Alice Corp'),
      ('acc_002', 75000.50, 'Bob LLC');
  `);

  const journal = new DurableEvidenceJournal();
  const stateFrontier = new DeterministicStateFrontier();
  const logicalClient = new PgLogicalClient(
    {
      connectionString: config.postgresUrl,
      slotName: 'wdb_acceptance_slot',
      plugin: 'pgoutput',
      protectedTables: ['public.accounts'],
    },
    journal,
    stateFrontier
  );

  const snapshot = await logicalClient.bootstrapFromClient(pgClient, ['public.accounts']);
  const baselineRootHex = snapshot.initialStateMerkleRoot.toString('hex');
  console.log(`  Bootstrap Snapshot LSN: ${snapshot.snapshotLsn}`);
  console.log(`  Initial State Merkle Root: 0x${baselineRootHex}`);

  // STAGE 5: Database Mutation
  console.log('\n[STAGE 5] Executing Database Mutation & Updating State Frontier...');
  await pgClient.query(`
    INSERT INTO public.accounts (id, balance, owner) VALUES ('acc_003', 120000.00, 'Charlie Global');
  `);

  const updatedSnapshot = await logicalClient.bootstrapFromClient(pgClient, ['public.accounts']);
  const updatedRootHex = updatedSnapshot.initialStateMerkleRoot.toString('hex');

  // STAGE 6: Canonical Commitment v3 Construction & Dual Attestation
  console.log('\n[STAGE 6] Constructing Canonical Trust Commitment v3 & Dual Signatures...');
  const agentKeyPair = crypto.generateKeyPairSync('ed25519');
  const agentPub = agentKeyPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

  const commitment: CanonicalTrustCommitmentV3 = {
    protocolVersion: 3,
    tenantId,
    databaseId,
    checkpointId: crypto.randomUUID(),
    commitSeq: 1n,
    epoch: 1,
    chainId: config.chainId,
    contractAddress: deployRes.contractAddress,
    networkId: 'wolverine-besu-cluster',
    checkpointDigestHex: crypto.randomBytes(32).toString('hex'),
    stateMerkleRootHex: updatedRootHex,
    changeChainHeadHex: crypto.randomBytes(32).toString('hex'),
    previousCommitmentDigestHex: '0'.repeat(64),
    logicalTimestampUs: BigInt(Date.now()) * 1000n,
    lsn: snapshot.snapshotLsn,
    agentId: 'agent_node_01',
    customerSigningAddress,
  };

  const digestHex = computeCanonicalCommitmentDigest(commitment);

  // Customer SECP256k1 EIP-712 Signature
  const custSig = await customerSigner.signTypedCommitment({
    chainId: commitment.chainId,
    verifyingContract: commitment.contractAddress as `0x${string}`,
    message: {
      tenantId: commitment.tenantId,
      databaseId: commitment.databaseId,
      commitSeq: commitment.commitSeq,
      epoch: commitment.epoch,
      checkpointId: formatHex16(commitment.checkpointId),
      checkpointDigest: formatHex32(commitment.checkpointDigestHex),
      stateMerkleRoot: formatHex32(commitment.stateMerkleRootHex),
      changeChainHead: formatHex32(commitment.changeChainHeadHex),
      previousCommitmentDigest: formatHex32(commitment.previousCommitmentDigestHex),
      logicalTimestampUs: commitment.logicalTimestampUs,
      lsn: commitment.lsn,
      agentId: commitment.agentId,
    },
  });

  // Agent Ed25519 Signature
  const agentPreimage = computeAgentAttestPreimage(commitment, digestHex);
  const agentSig = crypto.sign(null, agentPreimage, agentKeyPair.privateKey);

  // STAGE 7: On-Chain Besu Submission with Real Customer Signature
  console.log('\n[STAGE 7] Submitting Commitment to Besu QBFT...');
  const submitRes = await besuClient.submitCommitment({
    tenantId: commitment.tenantId,
    databaseId: commitment.databaseId,
    checkpointIdHex: commitment.checkpointId.replace(/-/g, ''),
    commitSeq: commitment.commitSeq,
    epoch: commitment.epoch,
    checkpointDigestHex: commitment.checkpointDigestHex,
    stateMerkleRootHex: commitment.stateMerkleRootHex,
    changeChainHeadHex: commitment.changeChainHeadHex,
    previousCommitmentDigestHex: commitment.previousCommitmentDigestHex,
    commitmentDigestHex: `0x${digestHex}`,
    logicalTimestampUs: commitment.logicalTimestampUs,
    lsn: commitment.lsn,
    agentId: commitment.agentId,
    protocolVersion: commitment.protocolVersion,
    agentSignatureHex: agentSig.toString('hex'),
    customerSignatureHex: custSig,
  });
  console.log(`  Besu Tx Hash:     ${submitRes.txHash}`);
  console.log(`  Finalized Block:  #${submitRes.blockNumber}`);
  console.log(`  Block Hash:       ${submitRes.blockHash}`);

  // STAGE 8: Universal Trust Receipt
  console.log('\n[STAGE 8] Generating Universal Trust Receipt...');
  const receipt = UniversalTrustReceiptGenerator.createReceipt({
    tenantId: commitment.tenantId,
    databaseId: commitment.databaseId,
    timestampUs: commitment.logicalTimestampUs.toString(),
    evidencePlane: {
      checkpointId: commitment.checkpointId,
      commitSeq: commitment.commitSeq.toString(),
      lsn: commitment.lsn,
      checkpointDigestHex: commitment.checkpointDigestHex,
      stateMerkleRootHex: commitment.stateMerkleRootHex,
      changeChainHeadHex: commitment.changeChainHeadHex,
      agentId: commitment.agentId,
      agentAttestationHex: agentSig.toString('hex'),
      customerSigningAddress,
      customerAuthorizationHex: custSig,
    },
    trustPlane: {
      networkId: commitment.networkId,
      chainId: commitment.chainId,
      blockchainTransactionHash: submitRes.txHash,
      blockNumber: submitRes.blockNumber.toString(),
      blockHash: submitRes.blockHash,
      finalityStatus: 'FINALIZED',
      contractAddress: submitRes.contractAddress,
      previousCommitmentDigestHex: commitment.previousCommitmentDigestHex,
    },
  });
  console.log(`  Receipt ID:       ${receipt.receiptId}`);
  console.log(`  Receipt Digest:   0x${receipt.receiptDigestHex}`);

  // STAGE 9: Offline Verification
  console.log('\n[STAGE 9] Executing Zero-Trust Offline Forensic Verification...');
  const verifyRes = await UniversalReceiptVerifier.verifyOffline({
    receipt,
    customerAddressOrPublicKey: customerSigningAddress,
    agentPublicKey: agentPub,
    currentDatabaseMerkleRootHex: updatedRootHex,
  });
  expect(verifyRes.isValid).toBe(true);
  expect(verifyRes.status).toBe('AUTHENTIC');
  console.log(`  Verification Status: ${verifyRes.status} (Self-Consistency & Cryptographic Bound Confirmed)`);

  // STAGE 10: Database Tampering Simulation
  console.log('\n[STAGE 10] Simulating Unauthorized Direct PostgreSQL DBA Tampering...');
  await pgClient.query(`
    UPDATE public.accounts SET balance = 9999999.99 WHERE id = 'acc_001';
  `);
  const tamperedSnapshot = await logicalClient.bootstrapFromClient(pgClient, ['public.accounts']);
  const tamperedRootHex = tamperedSnapshot.initialStateMerkleRoot.toString('hex');
  console.log(`  Tampered State Merkle Root: 0x${tamperedRootHex}`);

  const tamperingResult = await UniversalReceiptVerifier.verifyOffline({
    receipt,
    customerAddressOrPublicKey: customerSigningAddress,
    agentPublicKey: agentPub,
    currentDatabaseMerkleRootHex: tamperedRootHex,
  });
  expect(tamperingResult.isValid).toBe(false);
  expect(tamperingResult.status).toBe('LOCAL_TAMPERING_DETECTED');
  console.log(`  Tampering Detection Status: ${tamperingResult.status}`);
  console.log('  State Divergence Confirmed: Witnessed root does not match tampered database state.');

  // STAGE 11: Attempt Forged Gateway Submission (Rejection Test)
  console.log('\n[STAGE 11] Verifying On-Chain Rejection of Forged Gateway Submission...');
  let rejected = false;
  try {
    await besuClient.submitCommitment({
      tenantId: 'unregistered_attacker_tenant',
      databaseId,
      checkpointIdHex: '00000000000000000000000000000001',
      commitSeq: 1n,
      epoch: 1,
      checkpointDigestHex: '0'.repeat(64),
      stateMerkleRootHex: '0'.repeat(64),
      changeChainHeadHex: '0'.repeat(64),
      previousCommitmentDigestHex: '0'.repeat(64),
      commitmentDigestHex: `0x${'f'.repeat(64)}`,
      logicalTimestampUs: 1000n,
      lsn: '0/1',
      agentId: 'agent_01',
      protocolVersion: 3,
      agentSignatureHex: '00',
      customerSignatureHex: '11'.repeat(65),
    });
  } catch (err: any) {
    rejected = true;
    console.log(`  Unauthorized Tenant Rejected on Besu: ${err.message.slice(0, 80)}...`);
  }
  expect(rejected).toBe(true);

  // STAGE 12: Besu RPC Failover & Integrity
  console.log('\n[STAGE 12] Testing Besu RPC Pool Automatic Failover & Integrity...');
  const failoverPool = new BesuRpcPool({
    nodes: ['http://127.0.0.1:9999', config.besuRpcUrls[0]!],
    chainId: config.chainId,
    timeoutMs: 1000,
    maxRetries: 2,
    retryBackoffMs: 50,
  });
  const block = await failoverPool.executeWithFailover(async (_url, client) => client.getBlockNumber());
  console.log(`  RPC Failover Success: Successfully read Block #${block} after skipping offline endpoint.`);

  const integrityCheck = await failoverPool.verifyRpcIntegrity(block);
  expect(integrityCheck.isConsistent).toBe(true);
  console.log(`  RPC Integrity Verified: Block #${block} Hash = ${integrityCheck.blockHash}`);

  await pgClient.end();

  console.log('\n========================================================================');
  console.log('  LIVE ACCEPTANCE SUITE PASSED (12 / 12 STAGES VERIFIED)');
  console.log('========================================================================\n');
  return true;
}

function expect(val: any) {
  return {
    toBe: (expected: any) => {
      if (val !== expected) throw new Error(`Expected ${expected}, received ${val}`);
    },
    toHaveLength: (len: number) => {
      if (val.length !== len) throw new Error(`Expected length ${len}, received ${val.length}`);
    },
  };
}

if (process.argv[1]?.endsWith('live_acceptance.js') || process.argv[1]?.endsWith('live_acceptance.ts')) {
  runLiveAcceptanceSuite()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n❌ LIVE ACCEPTANCE SUITE FAILED:\n', err);
      process.exit(1);
    });
}
