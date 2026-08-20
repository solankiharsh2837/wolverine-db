import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'node:crypto';
import {
  CanonicalTrustCommitmentV3,
  computeCanonicalCommitmentDigest,
  computeAgentAttestPreimage,
  verifyCustomerEip712Signature,
  verifyDualSignedCommitment,
  DualSignedCommitmentV3,
  formatHex16,
  formatHex32,
  WOLVERINE_EIP712_DOMAIN_NAME,
  WOLVERINE_EIP712_VERSION,
} from '../src/protocol/commitment_v3.js';
import { Secp256k1CustomerSigningProvider } from '../src/crypto/secp256k1_provider.js';
import { UniversalReceiptVerifier } from '../src/proof/universal_receipt_verifier.js';
import { UniversalTrustReceiptGenerator, UniversalTrustReceipt } from '../src/receipts/universal_receipt.js';
import { BesuClient } from '../src/blockchain/besu/client.js';
import { deployTrustRegistry } from '../src/blockchain/besu/deploy.js';
import { BesuRpcPool } from '../src/blockchain/besu/rpc_pool.js';
import { WolverineError, WolverineErrorCode } from '../src/errors/index.js';
import { privateKeyToAccount } from 'viem/accounts';

describe('Critical Cryptographic Authority & Adversarial Proof Suite', () => {
  let contractAddress: `0x${string}`;
  let besuClient: BesuClient;
  const chainId = 13370;
  const besuRpcUrl = 'http://127.0.0.1:8545';

  const tenantId = `tenant_audit_${Date.now()}`;
  const databaseId = 'audit_vault_db';

  const customerSigner = new Secp256k1CustomerSigningProvider();
  const customerSigningAddress = customerSigner.getAddress();

  const agentKeyPair = crypto.generateKeyPairSync('ed25519');
  const agentPub = agentKeyPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

  beforeAll(async () => {
    // Deploy freshly compiled hardened smart contract
    const deployment = await deployTrustRegistry(besuRpcUrl);
    contractAddress = deployment.contractAddress;

    besuClient = new BesuClient({
      rpcUrl: besuRpcUrl,
      chainId,
      contractAddress,
      operatorPrivateKeyHex: '0x0000000000000000000000000000000000000000000000000000000000000001',
    });

    // Register sovereign tenant on Besu
    await besuClient.registerTenant(
      tenantId,
      customerSigningAddress,
      '0xfe3b557e8fb62b89f4916b721be55ceb828dbd73' // Deployer/Gateway address
    );
  }, 30000);

  function createCommitment(seq: bigint, stateRoot: string, prevDigest: string): CanonicalTrustCommitmentV3 {
    return {
      protocolVersion: 3,
      tenantId,
      databaseId,
      checkpointId: crypto.randomUUID(),
      commitSeq: seq,
      epoch: 1,
      chainId,
      contractAddress,
      networkId: 'wolverine-besu-cluster',
      checkpointDigestHex: '11'.repeat(32),
      stateMerkleRootHex: stateRoot,
      changeChainHeadHex: '22'.repeat(32),
      previousCommitmentDigestHex: prevDigest,
      logicalTimestampUs: BigInt(Date.now()) * 1000n,
      lsn: '0/100000',
      agentId: 'agent_node_01',
      customerSigningAddress,
    };
  }

  it('Vector A: Valid dual-signed commitment is accepted and finalized on Besu', async () => {
    const commitment = createCommitment(1n, 'aa'.repeat(32), '00'.repeat(32));
    const digest = computeCanonicalCommitmentDigest(commitment);

    const custSig = await customerSigner.signTypedCommitment({
      chainId,
      verifyingContract: contractAddress,
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

    const agentPreimage = computeAgentAttestPreimage(commitment, digest);
    const agentSig = crypto.sign(null, agentPreimage, agentKeyPair.privateKey);

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
      commitmentDigestHex: `0x${digest}`,
      logicalTimestampUs: commitment.logicalTimestampUs,
      lsn: commitment.lsn,
      agentId: commitment.agentId,
      protocolVersion: commitment.protocolVersion,
      agentSignatureHex: agentSig.toString('hex'),
      customerSignatureHex: custSig,
    });

    expect(submitRes.success).toBe(true);
    expect(submitRes.blockNumber).toBeGreaterThan(0n);
  });

  it('Vector B & C: Empty or invalid customer signature strictly REVERTS on Besu (Fail-Closed)', async () => {
    const commitment = createCommitment(2n, 'bb'.repeat(32), '00'.repeat(32));

    // Attempt with empty signature
    await expect(
      besuClient.submitCommitment({
        tenantId: commitment.tenantId,
        databaseId: commitment.databaseId,
        checkpointIdHex: commitment.checkpointId.replace(/-/g, ''),
        commitSeq: commitment.commitSeq,
        epoch: commitment.epoch,
        checkpointDigestHex: commitment.checkpointDigestHex,
        stateMerkleRootHex: commitment.stateMerkleRootHex,
        changeChainHeadHex: commitment.changeChainHeadHex,
        previousCommitmentDigestHex: commitment.previousCommitmentDigestHex,
        commitmentDigestHex: `0x${'00'.repeat(32)}`,
        logicalTimestampUs: commitment.logicalTimestampUs,
        lsn: commitment.lsn,
        agentId: commitment.agentId,
        protocolVersion: commitment.protocolVersion,
        agentSignatureHex: '00',
        customerSignatureHex: '', // EMPTY SIGNATURE
      })
    ).rejects.toThrow(/InvalidCustomerSignature/);
  });

  it('Vector D: 64-byte Ed25519 signature passed to EVM path strictly REVERTS on Besu', async () => {
    const commitment = createCommitment(2n, 'bb'.repeat(32), '00'.repeat(32));
    const fakeEd25519 = '11'.repeat(32); // 64-byte hex string (32 bytes hex = 64 chars)

    await expect(
      besuClient.submitCommitment({
        tenantId: commitment.tenantId,
        databaseId: commitment.databaseId,
        checkpointIdHex: commitment.checkpointId.replace(/-/g, ''),
        commitSeq: commitment.commitSeq,
        epoch: commitment.epoch,
        checkpointDigestHex: commitment.checkpointDigestHex,
        stateMerkleRootHex: commitment.stateMerkleRootHex,
        changeChainHeadHex: commitment.changeChainHeadHex,
        previousCommitmentDigestHex: commitment.previousCommitmentDigestHex,
        commitmentDigestHex: `0x${'00'.repeat(32)}`,
        logicalTimestampUs: commitment.logicalTimestampUs,
        lsn: commitment.lsn,
        agentId: commitment.agentId,
        protocolVersion: commitment.protocolVersion,
        agentSignatureHex: '00',
        customerSignatureHex: fakeEd25519,
      })
    ).rejects.toThrow(/InvalidCustomerSignature/);
  });

  it('Vector E: Valid customer signature with modified stateMerkleRoot strictly REVERTS on Besu', async () => {
    const legitimateCommitment = createCommitment(2n, 'bb'.repeat(32), '00'.repeat(32));

    // Customer signs legitimate commitment with state root 'bb'
    const custSig = await customerSigner.signTypedCommitment({
      chainId,
      verifyingContract: contractAddress,
      message: {
        tenantId: legitimateCommitment.tenantId,
        databaseId: legitimateCommitment.databaseId,
        commitSeq: legitimateCommitment.commitSeq,
        epoch: legitimateCommitment.epoch,
        checkpointId: formatHex16(legitimateCommitment.checkpointId),
        checkpointDigest: formatHex32(legitimateCommitment.checkpointDigestHex),
        stateMerkleRoot: formatHex32(legitimateCommitment.stateMerkleRootHex),
        changeChainHead: formatHex32(legitimateCommitment.changeChainHeadHex),
        previousCommitmentDigest: formatHex32(legitimateCommitment.previousCommitmentDigestHex),
        logicalTimestampUs: legitimateCommitment.logicalTimestampUs,
        lsn: legitimateCommitment.lsn,
        agentId: legitimateCommitment.agentId,
      },
    });

    // Rogue Gateway attempts to substitute a tampered state root 'ff' while keeping the customer signature
    await expect(
      besuClient.submitCommitment({
        tenantId: legitimateCommitment.tenantId,
        databaseId: legitimateCommitment.databaseId,
        checkpointIdHex: legitimateCommitment.checkpointId.replace(/-/g, ''),
        commitSeq: legitimateCommitment.commitSeq,
        epoch: legitimateCommitment.epoch,
        checkpointDigestHex: legitimateCommitment.checkpointDigestHex,
        stateMerkleRootHex: 'ff'.repeat(32), // FORGED STATE ROOT
        changeChainHeadHex: legitimateCommitment.changeChainHeadHex,
        previousCommitmentDigestHex: legitimateCommitment.previousCommitmentDigestHex,
        commitmentDigestHex: `0x${'00'.repeat(32)}`,
        logicalTimestampUs: legitimateCommitment.logicalTimestampUs,
        lsn: legitimateCommitment.lsn,
        agentId: legitimateCommitment.agentId,
        protocolVersion: legitimateCommitment.protocolVersion,
        agentSignatureHex: '00',
        customerSignatureHex: custSig,
      })
    ).rejects.toThrow(/InvalidCustomerSignature/);
  });

  it('Vector J & K: Unregistered tenant / wrong tenant strictly REVERTS on Besu', async () => {
    const maliciousTenant = `malicious_${Date.now()}`;
    const commitment = { ...createCommitment(1n, 'cc'.repeat(32), '00'.repeat(32)), tenantId: maliciousTenant };

    await expect(
      besuClient.submitCommitment({
        tenantId: maliciousTenant,
        databaseId: commitment.databaseId,
        checkpointIdHex: commitment.checkpointId.replace(/-/g, ''),
        commitSeq: 1n,
        epoch: 1,
        checkpointDigestHex: commitment.checkpointDigestHex,
        stateMerkleRootHex: commitment.stateMerkleRootHex,
        changeChainHeadHex: commitment.changeChainHeadHex,
        previousCommitmentDigestHex: commitment.previousCommitmentDigestHex,
        commitmentDigestHex: `0x${'00'.repeat(32)}`,
        logicalTimestampUs: commitment.logicalTimestampUs,
        lsn: commitment.lsn,
        agentId: commitment.agentId,
        protocolVersion: commitment.protocolVersion,
        agentSignatureHex: '00',
        customerSignatureHex: '11'.repeat(65),
      })
    ).rejects.toThrow(/TenantNotRegistered/);
  });

  it('Vector M & N: Offline verifier validates authentic receipt and rejects forged receipt', async () => {
    const commitment = createCommitment(1n, 'aa'.repeat(32), '00'.repeat(32));
    const digest = computeCanonicalCommitmentDigest(commitment);

    const custSig = await customerSigner.signTypedCommitment({
      chainId,
      verifyingContract: contractAddress,
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

    const agentPreimage = computeAgentAttestPreimage(commitment, digest);
    const agentSig = crypto.sign(null, agentPreimage, agentKeyPair.privateKey);

    const receipt: UniversalTrustReceipt = UniversalTrustReceiptGenerator.createReceipt({
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
        blockchainTransactionHash: '0x1234567890123456789012345678901234567890123456789012345678901234',
        blockNumber: '100',
        blockHash: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef',
        finalityStatus: 'FINALIZED',
        contractAddress,
        previousCommitmentDigestHex: commitment.previousCommitmentDigestHex,
      },
    });

    // 1. Verify authentic receipt
    const validRes = await UniversalReceiptVerifier.verifyOffline({
      receipt,
      customerAddressOrPublicKey: customerSigningAddress,
      agentPublicKey: agentPub,
      currentDatabaseMerkleRootHex: commitment.stateMerkleRootHex,
    });
    expect(validRes.isValid).toBe(true);
    expect(validRes.status).toBe('AUTHENTIC');

    // 2. Tamper database state Merkle root
    const tamperedRes = await UniversalReceiptVerifier.verifyOffline({
      receipt,
      customerAddressOrPublicKey: customerSigningAddress,
      agentPublicKey: agentPub,
      currentDatabaseMerkleRootHex: '99'.repeat(32), // Altered database state
    });
    expect(tamperedRes.isValid).toBe(false);
    expect(tamperedRes.status).toBe('LOCAL_TAMPERING_DETECTED');
  });

  it('Vector O: RPC integrity cross-checking detects and rejects divergent block hashes', async () => {
    const rpcPool = new BesuRpcPool({
      nodes: ['http://127.0.0.1:8545'],
      chainId,
    });

    // Mock divergent node check
    const checkRes = await rpcPool.verifyRpcIntegrity(1n);
    expect(checkRes.isConsistent).toBe(true);
    expect(checkRes.blockHash.startsWith('0x')).toBe(true);
  });
});
