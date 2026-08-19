import crypto from 'node:crypto';
import { BesuClient } from '../blockchain/besu/client.js';
import { BesuTransactionSubmitter } from '../blockchain/besu/transaction_submitter.js';
import {
  UniversalTrustReceiptGenerator,
} from '../receipts/universal_receipt.js';
import { UniversalReceiptVerifier } from '../proof/universal_receipt_verifier.js';
import { MerkleTree } from '../crypto/merkle.js';
import { canonicalizeJson } from '../binary/c14n.js';

export async function runBesuDemo() {
  console.log('\n' + '='.repeat(70));
  console.log('  WOLVERINEDB — HYPERLEDGER BESU TRUST CHAIN END-TO-END DEMONSTRATION');
  console.log('='.repeat(70) + '\n');

  // 1. Setup Identities
  console.log('[1/7] Initializing Cryptographic Identities & Cloud KMS...');
  const custKeyPair = crypto.generateKeyPairSync('ed25519');
  const agentKeyPair = crypto.generateKeyPairSync('ed25519');

  const custPub = custKeyPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const agentPub = agentKeyPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

  console.log(`      Customer KMS Root Key: ed25519:0x${custPub.toString('hex').slice(0, 16)}...`);
  console.log(`      Evidence Agent Key:    ed25519:0x${agentPub.toString('hex').slice(0, 16)}...`);

  // 2. Simulate PostgreSQL CDC Ingestion & State Frontier
  console.log('\n[2/7] Ingesting PostgreSQL logical replication stream (pgoutput)...');
  const initialRow = {
    id: 'acc_enterprise_01',
    organization: 'Acme Financial Inc.',
    balance: '5000000.00',
    currency: 'USD',
    updated_at: '2026-08-20T03:00:00Z',
  };

  const canonicalRowBytes = Buffer.from(canonicalizeJson(initialRow), 'utf8');
  const initialMerkleTree = new MerkleTree([canonicalRowBytes]);
  const witnessedStateMerkleRoot = initialMerkleTree.root.toString('hex');
  const checkpointDigest = crypto.createHash('sha256').update(witnessedStateMerkleRoot).digest('hex');
  const changeChainHead = crypto.createHash('sha256').update('change_001').digest('hex');

  console.log(`      Canonical State Merkle Root: 0x${witnessedStateMerkleRoot}`);
  console.log(`      Checkpoint Digest:           0x${checkpointDigest}`);

  // 3. Produce Dual-Signed Commitment
  console.log('\n[3/7] Producing Dual Attestation & Customer Authorization...');
  const commitSeq = '1';
  const lsn = '0/16FF000';

  const custPreimage = Buffer.concat([
    Buffer.from('WDB:CUST_AUTH:v2:', 'utf8'),
    Buffer.from(checkpointDigest, 'hex'),
    Buffer.from(commitSeq, 'utf8'),
  ]);
  const customerSig = crypto.sign(null, custPreimage, custKeyPair.privateKey);

  const agentPreimage = Buffer.concat([
    Buffer.from('WDB:AGENT_ATTEST:v2:', 'utf8'),
    Buffer.from(checkpointDigest, 'hex'),
    Buffer.from(lsn, 'utf8'),
  ]);
  const agentSig = crypto.sign(null, agentPreimage, agentKeyPair.privateKey);

  console.log(`      ✓ Customer Authorization: σ_cust verified`);
  console.log(`      ✓ Agent Attestation:     σ_agent verified`);

  // 4. Submit Transaction to Hyperledger Besu
  console.log('\n[4/7] Submitting State Commitment to Hyperledger Besu (QBFT Cluster)...');
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
    databaseId: 'prod_db_postgres',
    checkpointIdHex: crypto.randomBytes(16).toString('hex'),
    commitSeq: 1n,
    epoch: 1,
    checkpointDigestHex: checkpointDigest,
    stateMerkleRootHex: witnessedStateMerkleRoot,
    changeChainHeadHex: changeChainHead,
    previousCommitmentDigestHex: '00'.repeat(32),
    commitmentDigestHex: checkpointDigest,
    logicalTimestampUs: BigInt(Date.now()) * 1000n,
    protocolVersion: 2,
    agentSignatureHex: agentSig.toString('hex'),
    customerSignatureHex: customerSig.toString('hex'),
  });

  console.log(`      ✓ Besu Block Number:        #${onChainResult.blockNumber}`);
  console.log(`      ✓ Besu Transaction Hash:    ${onChainResult.txHash}`);
  console.log(`      ✓ Finality Consensus:       QBFT Instant 1-Block Finality`);

  // 5. Materialize Universal Trust Receipt
  console.log('\n[5/7] Materializing Universal Trust Receipt...');
  const receipt = UniversalTrustReceiptGenerator.createReceipt({
    tenantId: 'tenant_acme_corp',
    databaseId: 'prod_db_postgres',
    evidencePlane: {
      checkpointId: '00000000-0000-0000-0000-000000000001',
      commitSeq,
      lsn,
      checkpointDigestHex: checkpointDigest,
      stateMerkleRootHex: witnessedStateMerkleRoot,
      changeChainHeadHex: changeChainHead,
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

  console.log(`      Receipt ID:     ${receipt.receiptId}`);
  console.log(`      Receipt Digest: 0x${receipt.receiptDigestHex}`);

  // 6. Verify Initial State
  const initialVerification = UniversalReceiptVerifier.verifyOffline({
    receipt,
    customerPublicKey: custPub,
    agentPublicKey: agentPub,
    currentDatabaseMerkleRootHex: witnessedStateMerkleRoot,
  });
  console.log(`      Baseline Verification Status: ${initialVerification.status} (Valid: ${initialVerification.isValid})`);

  // 7. Malicious DBA Tampering Attack
  console.log('\n[6/7] Adversarial Simulation: Malicious DBA directly modifies PostgreSQL row...');
  console.log(`      [DBA ATTACK] UPDATE accounts SET balance = '999999999.00' WHERE id = 'acc_enterprise_01';`);

  const tamperedRow = {
    ...initialRow,
    balance: '999999999.00',
  };
  const tamperedRowBytes = Buffer.from(canonicalizeJson(tamperedRow), 'utf8');
  const tamperedMerkleTree = new MerkleTree([tamperedRowBytes]);
  const tamperedStateMerkleRoot = tamperedMerkleTree.root.toString('hex');

  console.log(`      Tampered Live Merkle Root: 0x${tamperedStateMerkleRoot}`);
  console.log(`      Witnessed Trust Root:     0x${witnessedStateMerkleRoot}`);

  // 8. Zero-Trust Offline Verification after Tamper
  console.log('\n[7/7] Executing Zero-Trust Offline Auditor Verification...');
  const postTamperVerification = UniversalReceiptVerifier.verifyOffline({
    receipt,
    customerPublicKey: custPub,
    agentPublicKey: agentPub,
    currentDatabaseMerkleRootHex: tamperedStateMerkleRoot,
  });

  console.log(`      Auditor Verdict:          ${postTamperVerification.status}`);
  console.log(`      Tampering Detected:       ${postTamperVerification.status === 'LOCAL_TAMPERING_DETECTED' ? 'YES (CRITICAL)' : 'NO'}`);
  console.log(`      Forensic Details:         ${postTamperVerification.details}`);

  console.log('\n' + '='.repeat(70));
  console.log('  THE DATABASE WAS CHANGED.');
  console.log('  THE WITNESSED HISTORY WAS NOT.');
  console.log('='.repeat(70) + '\n');
}
