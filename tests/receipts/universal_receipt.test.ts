import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  UniversalTrustReceiptGenerator,
  UniversalTrustReceipt,
} from '../../src/receipts/universal_receipt.js';
import { UniversalReceiptVerifier } from '../../src/proof/universal_receipt_verifier.js';

describe('Universal Trust Receipt & Zero-Trust Offline Verifier', () => {
  const custPair = crypto.generateKeyPairSync('ed25519');
  const agentPair = crypto.generateKeyPairSync('ed25519');

  const custPub = custPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const agentPub = agentPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

  const checkpointDigestHex = crypto.createHash('sha256').update('chk_001').digest('hex');
  const stateMerkleRootHex = crypto.createHash('sha256').update('merkle_state_v1').digest('hex');
  const changeChainHeadHex = crypto.createHash('sha256').update('chain_head_v1').digest('hex');
  const commitSeq = '1';
  const lsn = '0/1600000';

  // Customer authorization signature
  const custPreimage = Buffer.concat([
    Buffer.from('WDB:CUST_AUTH:v2:', 'utf8'),
    Buffer.from(checkpointDigestHex, 'hex'),
    Buffer.from(commitSeq, 'utf8'),
  ]);
  const customerAuthSig = crypto.sign(null, custPreimage, custPair.privateKey);

  // Agent attestation signature
  const agentPreimage = Buffer.concat([
    Buffer.from('WDB:AGENT_ATTEST:v2:', 'utf8'),
    Buffer.from(checkpointDigestHex, 'hex'),
    Buffer.from(lsn, 'utf8'),
  ]);
  const agentAttestSig = crypto.sign(null, agentPreimage, agentPair.privateKey);

  const receipt = UniversalTrustReceiptGenerator.createReceipt({
    tenantId: 'enterprise_bank_01',
    databaseId: 'core_ledger',
    evidencePlane: {
      checkpointId: '00000000-0000-0000-0000-000000000001',
      commitSeq,
      lsn,
      checkpointDigestHex,
      stateMerkleRootHex,
      changeChainHeadHex,
      agentAttestationHex: agentAttestSig.toString('hex'),
      customerAuthorizationHex: customerAuthSig.toString('hex'),
    },
    trustPlane: {
      networkId: 'wolverine-besu-cluster',
      chainId: 13370,
      blockchainTransactionHash: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      blockNumber: '42',
      blockHash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
      finalityStatus: 'FINALIZED',
      contractAddress: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
      previousCommitmentDigestHex: '0000000000000000000000000000000000000000000000000000000000000000',
    },
  });

  it('verifies an authentic receipt against valid matching database Merkle root', () => {
    const result = UniversalReceiptVerifier.verifyOffline({
      receipt,
      customerPublicKey: custPub,
      agentPublicKey: agentPub,
      currentDatabaseMerkleRootHex: stateMerkleRootHex,
    });

    expect(result.isValid).toBe(true);
    expect(result.status).toBe('AUTHENTIC');
  });

  it('detects local database tampering when live Merkle root diverges from witnessed root', () => {
    const tamperedRootHex = crypto.createHash('sha256').update('unauthorized_dba_edit').digest('hex');

    const result = UniversalReceiptVerifier.verifyOffline({
      receipt,
      customerPublicKey: custPub,
      agentPublicKey: agentPub,
      currentDatabaseMerkleRootHex: tamperedRootHex,
    });

    expect(result.isValid).toBe(false);
    expect(result.status).toBe('LOCAL_TAMPERING_DETECTED');
    expect(result.witnessedStateMerkleRootHex).toBe(stateMerkleRootHex);
    expect(result.evaluatedStateMerkleRootHex).toBe(tamperedRootHex);
  });

  it('rejects forged customer signature', () => {
    const badKey = crypto.generateKeyPairSync('ed25519');
    const forgedReceipt: UniversalTrustReceipt = {
      ...receipt,
      evidencePlane: {
        ...receipt.evidencePlane,
        customerAuthorizationHex: crypto.sign(null, custPreimage, badKey.privateKey).toString('hex'),
      },
    };
    // Recompute digest for modified receipt
    const validInternalDigest = UniversalTrustReceiptGenerator.createReceipt(forgedReceipt);

    const result = UniversalReceiptVerifier.verifyOffline({
      receipt: validInternalDigest,
      customerPublicKey: custPub,
      agentPublicKey: agentPub,
    });

    expect(result.isValid).toBe(false);
    expect(result.status).toBe('INVALID_CUSTOMER_SIGNATURE');
  });

  it('detects receipt corruption', () => {
    const corruptedReceipt = {
      ...receipt,
      receiptDigestHex: 'deadbeef00000000000000000000000000000000000000000000000000000000',
    };

    const result = UniversalReceiptVerifier.verifyOffline({
      receipt: corruptedReceipt,
      customerPublicKey: custPub,
      agentPublicKey: agentPub,
    });

    expect(result.isValid).toBe(false);
    expect(result.status).toBe('RECEIPT_CORRUPTED');
  });
});
