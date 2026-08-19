import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { BesuClient } from '../../src/blockchain/besu/client.js';
import { BesuTransactionSubmitter } from '../../src/blockchain/besu/transaction_submitter.js';
import { BesuStateCommitmentInput } from '../../src/blockchain/besu/types.js';

describe('Hyperledger Besu Authoritative Blockchain Subsystem', () => {
  const contractAddress = '0x5FbDB2315678afecb367f032d93F642f64180aa3';
  const tenantId = 'enterprise_acme_corp';
  const databaseId = 'primary_ledger';

  it('submits valid dual-signed state commitment to Besu transaction submitter', async () => {
    let capturedMethod = '';
    let capturedParams: any[] = [];

    const mockRpcHandler = async (method: string, params: any[]) => {
      capturedMethod = method;
      capturedParams = params;
      return {
        success: true,
        txHash: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        blockNumber: 101n,
        blockHash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        commitmentDigestHex: params[0].commitmentDigestHex,
        contractAddress,
      };
    };

    const client = new BesuClient(
      {
        rpcUrl: 'http://127.0.0.1:8545',
        chainId: 13370,
        contractAddress,
      },
      mockRpcHandler
    );

    const submitter = new BesuTransactionSubmitter(client);

    const input: BesuStateCommitmentInput = {
      tenantId,
      databaseId,
      checkpointIdHex: crypto.randomBytes(16).toString('hex'),
      commitSeq: 1n,
      epoch: 1,
      checkpointDigestHex: crypto.createHash('sha256').update('chk_1').digest('hex'),
      stateMerkleRootHex: crypto.createHash('sha256').update('state_1').digest('hex'),
      changeChainHeadHex: crypto.createHash('sha256').update('chain_1').digest('hex'),
      previousCommitmentDigestHex: '0000000000000000000000000000000000000000000000000000000000000000',
      commitmentDigestHex: crypto.createHash('sha256').update('commit_1').digest('hex'),
      logicalTimestampUs: BigInt(Date.now()) * 1000n,
      protocolVersion: 2,
      agentSignatureHex: crypto.randomBytes(64).toString('hex'),
      customerSignatureHex: crypto.randomBytes(64).toString('hex'),
    };

    const res = await submitter.submitStateCommitment(input);

    expect(res.success).toBe(true);
    expect(res.blockNumber).toBe(101n);
    expect(res.txHash).toBe('0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
    expect(capturedMethod).toBe('commitState');
    expect(capturedParams[0].tenantId).toBe(tenantId);
  });

  it('rejects commitment missing customer signature or agent attestation', async () => {
    const client = new BesuClient({
      rpcUrl: 'http://127.0.0.1:8545',
      chainId: 13370,
      contractAddress,
    });
    const submitter = new BesuTransactionSubmitter(client);

    const missingCustomerSigInput: BesuStateCommitmentInput = {
      tenantId,
      databaseId,
      checkpointIdHex: crypto.randomBytes(16).toString('hex'),
      commitSeq: 1n,
      epoch: 1,
      checkpointDigestHex: 'aa',
      stateMerkleRootHex: 'bb',
      changeChainHeadHex: 'cc',
      previousCommitmentDigestHex: '00',
      commitmentDigestHex: 'dd',
      logicalTimestampUs: 1000n,
      protocolVersion: 2,
      agentSignatureHex: 'ee',
      customerSignatureHex: '', // Missing!
    };

    await expect(submitter.submitStateCommitment(missingCustomerSigInput)).rejects.toThrowError(
      /Missing required customer authorization signature/
    );
  });
});
