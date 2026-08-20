import crypto from 'node:crypto';
import { BesuClient } from '../blockchain/besu/client.js';
import { BesuTransactionSubmitter } from '../blockchain/besu/transaction_submitter.js';
import {
  UniversalTrustReceiptGenerator,
} from '../receipts/universal_receipt.js';
import { UniversalReceiptVerifier } from '../proof/universal_receipt_verifier.js';
import { MerkleTree } from '../crypto/merkle.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { LocalDevelopmentSigningProvider } from '../crypto/dev_signing_provider.js';

export async function runBesuSimulatedDemo() {
  console.log('\n' + '='.repeat(70));
  console.log('  WOLVERINEDB — BESU TRUST CHAIN OFFLINE SIMULATION DEMO');
  console.log('  [NOTICE: SIMULATION ONLY — RUN npm run demo:besu-live FOR LIVE BLOCKCHAIN]');
  console.log('='.repeat(70) + '\n');

  process.env.WOLVERINE_DEV_SIGNER = '1';
  const customerSigner = new LocalDevelopmentSigningProvider({ allowDevSigner: true });
  const agentKeyPair = crypto.generateKeyPairSync('ed25519');

  const custPub = customerSigner.getPublicKey();
  const agentPub = agentKeyPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

  const initialRow = {
    account_id: '101',
    organization: 'Acme Financial Treasury',
    balance: '10000.00',
    currency: 'USD',
    updated_at: '2026-08-20T03:30:00Z',
  };

  const canonicalRowBytes = Buffer.from(canonicalizeJson(initialRow), 'utf8');
  const initialMerkleTree = new MerkleTree([canonicalRowBytes]);
  const witnessedStateMerkleRoot = initialMerkleTree.root.toString('hex');
  const checkpointDigest = crypto.createHash('sha256').update(witnessedStateMerkleRoot).digest('hex');
  const changeChainHead = crypto.createHash('sha256').update('change_seq_001').digest('hex');

  const commitSeq = 1n;
  const lsn = '0/1700000';

  const custPreimage = Buffer.concat([
    Buffer.from('WDB:CUST_AUTH:v2:', 'utf8'),
    Buffer.from(checkpointDigest, 'hex'),
    Buffer.from(commitSeq.toString(), 'utf8'),
  ]);
  const customerSig = await customerSigner.sign(custPreimage);

  const agentPreimage = Buffer.concat([
    Buffer.from('WDB:AGENT_ATTEST:v2:', 'utf8'),
    Buffer.from(checkpointDigest, 'hex'),
    Buffer.from(lsn, 'utf8'),
  ]);
  const agentSig = crypto.sign(null, agentPreimage, agentKeyPair.privateKey);

  const contractAddress = '0x5FbDB2315678afecb367f032d93F642f64180aa3';
  const mockRpc = async (method: string, params: any[]) => {
    return {
      success: true,
      txHash: '0x8b3f5c9e2d1a4b7e8c3f5c9e2d1a4b7e8c3f5c9e2d1a4b7e8c3f5c9e2d1a4b7e',
      blockNumber: 4281n,
      blockHash: '0x99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff',
      commitmentDigestHex: checkpointDigest,
      contractAddress,
    };
  };

  const besuClient = new BesuClient(
    { rpcUrl: 'http://127.0.0.1:8545', chainId: 13370, contractAddress },
    mockRpc
  );
  const submitter = new BesuTransactionSubmitter(besuClient);

  const onChainResult = await submitter.submitStateCommitment({
    tenantId: 'tenant_acme_corp',
    databaseId: 'core_postgres',
    checkpointIdHex: crypto.randomBytes(16).toString('hex'),
    commitSeq,
    epoch: 1,
    checkpointDigestHex: checkpointDigest,
    stateMerkleRootHex: witnessedStateMerkleRoot,
    changeChainHeadHex: changeChainHead,
    previousCommitmentDigestHex: '00'.repeat(32),
    commitmentDigestHex: checkpointDigest,
    logicalTimestampUs: BigInt(Date.now()) * 1000n,
    lsn,
    agentId: 'agent_node_01',
    protocolVersion: 2,
    agentSignatureHex: agentSig.toString('hex'),
    customerSignatureHex: customerSig.toString('hex'),
  });

  const receipt = UniversalTrustReceiptGenerator.createReceipt({
    tenantId: 'tenant_acme_corp',
    databaseId: 'core_postgres',
    evidencePlane: {
      checkpointId: '00000000-0000-0000-0000-000000000001',
      commitSeq: commitSeq.toString(),
      lsn,
      checkpointDigestHex: checkpointDigest,
      stateMerkleRootHex: witnessedStateMerkleRoot,
      changeChainHeadHex: changeChainHead,
      agentId: 'agent_node_01',
      agentAttestationHex: agentSig.toString('hex'),
      customerAuthorizationHex: customerSig.toString('hex'),
    },
    trustPlane: {
      networkId: 'wolverine-besu-cluster',
      chainId: 13370,
      blockchainTransactionHash: onChainResult.txHash,
      blockNumber: onChainResult.blockNumber.toString(),
      blockHash: onChainResult.blockHash,
      finalityStatus: 'FINALIZED',
      contractAddress,
      previousCommitmentDigestHex: '00'.repeat(32),
    },
  });

  const tamperedRow = {
    ...initialRow,
    balance: '100000000.00',
  };
  const tamperedRowBytes = Buffer.from(canonicalizeJson(tamperedRow), 'utf8');
  const tamperedMerkleTree = new MerkleTree([tamperedRowBytes]);
  const tamperedStateMerkleRoot = tamperedMerkleTree.root.toString('hex');

  const offlineAudit = await UniversalReceiptVerifier.verifyOffline({
    receipt,
    customerAddressOrPublicKey: custPub,
    agentPublicKey: agentPub,
    currentDatabaseMerkleRootHex: tamperedStateMerkleRoot,
  });

  console.log('\n' + '='.repeat(68));
  console.log('        WOLVERINEDB SIMULATED TRUST CHAIN DEMONSTRATION');
  console.log('        [SIMULATION ONLY — RUN demo:besu-live FOR REAL BESU]');
  console.log('='.repeat(68));
  console.log(`\nOriginal Database State:`);
  console.log(`    $10,000.00`);
  console.log(`\nWitnessed State Root:`);
  console.log(`    0x${witnessedStateMerkleRoot}`);
  console.log(`\nTransaction (Simulated):`);
  console.log(`    ${onChainResult.txHash}`);
  console.log(`\nBlock (Simulated):`);
  console.log(`    #${onChainResult.blockNumber}`);
  console.log(`\nUniversal Trust Receipt:`);
  console.log(`    rcpt-${receipt.receiptId}`);
  console.log('\n------------------------------------------------------------');
  console.log('\nDATABASE WAS MODIFIED AFTER WITNESSING');
  console.log(`\nCurrent Live State:`);
  console.log(`    $100,000,000.00`);
  console.log(`\nReceipt Witnessed State:`);
  console.log(`    $10,000.00`);
  console.log(`\nCurrent Database:`);
  console.log(`    DIVERGED (${offlineAudit.status})`);
  console.log('\nVERDICT:');
  console.log('    THE DATABASE WAS CHANGED.');
  console.log('    THE WITNESSED HISTORY WAS NOT.');
  console.log('='.repeat(68) + '\n');
}

if (process.argv[1]?.endsWith('besu_simulated_demo.js') || process.argv[1]?.endsWith('besu_simulated_demo.ts')) {
  runBesuSimulatedDemo().catch((err) => {
    console.error('Fatal simulation failure:', err.message);
    process.exit(1);
  });
}
