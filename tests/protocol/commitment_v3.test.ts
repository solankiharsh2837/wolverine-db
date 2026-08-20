import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  CanonicalTrustCommitmentV3,
  computeCanonicalCommitmentDigest,
  computeEip712CommitmentDigest,
  computeAgentAttestPreimage,
  verifyCustomerEip712Signature,
  verifyDualSignedCommitment,
  DualSignedCommitmentV3,
  formatHex16,
  formatHex32,
} from '../../src/protocol/commitment_v3.js';
import { Secp256k1CustomerSigningProvider } from '../../src/crypto/secp256k1_provider.js';

describe('Canonical Trust Commitment Schema v3 & EIP-712 Authority', () => {
  const customerSigner = new Secp256k1CustomerSigningProvider(
    '0x0000000000000000000000000000000000000000000000000000000000000042'
  );
  const customerSigningAddress = customerSigner.getAddress();

  const baseCommitment: CanonicalTrustCommitmentV3 = {
    protocolVersion: 3,
    tenantId: 'tenant_acme_corp',
    databaseId: 'core_postgres',
    checkpointId: '00000000-0000-0000-0000-000000000001',
    commitSeq: 1n,
    epoch: 1,
    chainId: 13370,
    contractAddress: '0xf2e246bb76df876cef8b38ae84130f4f55de395b',
    networkId: 'wolverine-besu-cluster',
    checkpointDigestHex: 'a'.repeat(64),
    stateMerkleRootHex: 'b'.repeat(64),
    changeChainHeadHex: 'c'.repeat(64),
    previousCommitmentDigestHex: '0'.repeat(64),
    logicalTimestampUs: 1787178850000000n,
    lsn: '0/1800000',
    agentId: 'agent_node_01',
    customerSigningAddress,
  };

  it('computes deterministic canonical commitment digest (Golden Vector)', () => {
    const digest1 = computeCanonicalCommitmentDigest(baseCommitment);
    const digest2 = computeCanonicalCommitmentDigest({ ...baseCommitment });

    expect(digest1).toBe(digest2);
    expect(digest1).toHaveLength(64);
  });

  it('computes deterministic EIP-712 structured data hash', () => {
    const hash1 = computeEip712CommitmentDigest(baseCommitment);
    const hash2 = computeEip712CommitmentDigest({ ...baseCommitment });

    expect(hash1).toBe(hash2);
    expect(hash1.startsWith('0x')).toBe(true);
    expect(hash1).toHaveLength(66);
  });

  it('verifies valid customer SECP256k1 EIP-712 signature', async () => {
    const custSig = await customerSigner.signTypedCommitment({
      chainId: baseCommitment.chainId,
      verifyingContract: baseCommitment.contractAddress as `0x${string}`,
      message: {
        tenantId: baseCommitment.tenantId,
        databaseId: baseCommitment.databaseId,
        commitSeq: baseCommitment.commitSeq,
        epoch: baseCommitment.epoch,
        checkpointId: formatHex16(baseCommitment.checkpointId),
        checkpointDigest: formatHex32(baseCommitment.checkpointDigestHex),
        stateMerkleRoot: formatHex32(baseCommitment.stateMerkleRootHex),
        changeChainHead: formatHex32(baseCommitment.changeChainHeadHex),
        previousCommitmentDigest: formatHex32(baseCommitment.previousCommitmentDigestHex),
        logicalTimestampUs: baseCommitment.logicalTimestampUs,
        lsn: baseCommitment.lsn,
        agentId: baseCommitment.agentId,
      },
    });

    const res = await verifyCustomerEip712Signature(baseCommitment, custSig, customerSigningAddress);
    expect(res.isValid).toBe(true);
    expect(res.recoveredAddress?.toLowerCase()).toBe(customerSigningAddress.toLowerCase());
  });

  it('rejects customer signature if stateMerkleRoot is tampered', async () => {
    const custSig = await customerSigner.signTypedCommitment({
      chainId: baseCommitment.chainId,
      verifyingContract: baseCommitment.contractAddress as `0x${string}`,
      message: {
        tenantId: baseCommitment.tenantId,
        databaseId: baseCommitment.databaseId,
        commitSeq: baseCommitment.commitSeq,
        epoch: baseCommitment.epoch,
        checkpointId: formatHex16(baseCommitment.checkpointId),
        checkpointDigest: formatHex32(baseCommitment.checkpointDigestHex),
        stateMerkleRoot: formatHex32(baseCommitment.stateMerkleRootHex),
        changeChainHead: formatHex32(baseCommitment.changeChainHeadHex),
        previousCommitmentDigest: formatHex32(baseCommitment.previousCommitmentDigestHex),
        logicalTimestampUs: baseCommitment.logicalTimestampUs,
        lsn: baseCommitment.lsn,
        agentId: baseCommitment.agentId,
      },
    });

    // Tamper with stateMerkleRoot
    const tamperedCommitment = {
      ...baseCommitment,
      stateMerkleRootHex: 'f'.repeat(64),
    };

    const res = await verifyCustomerEip712Signature(tamperedCommitment, custSig, customerSigningAddress);
    expect(res.isValid).toBe(false);
  });

  it('verifies valid dual-signed commitment (SECP256k1 Customer + Ed25519 Agent)', async () => {
    const agentKeyPair = crypto.generateKeyPairSync('ed25519');
    const agentPub = agentKeyPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    const digest = computeCanonicalCommitmentDigest(baseCommitment);
    const agentPreimage = computeAgentAttestPreimage(baseCommitment, digest);
    const agentSig = crypto.sign(null, agentPreimage, agentKeyPair.privateKey);

    const custSig = await customerSigner.signTypedCommitment({
      chainId: baseCommitment.chainId,
      verifyingContract: baseCommitment.contractAddress as `0x${string}`,
      message: {
        tenantId: baseCommitment.tenantId,
        databaseId: baseCommitment.databaseId,
        commitSeq: baseCommitment.commitSeq,
        epoch: baseCommitment.epoch,
        checkpointId: formatHex16(baseCommitment.checkpointId),
        checkpointDigest: formatHex32(baseCommitment.checkpointDigestHex),
        stateMerkleRoot: formatHex32(baseCommitment.stateMerkleRootHex),
        changeChainHead: formatHex32(baseCommitment.changeChainHeadHex),
        previousCommitmentDigest: formatHex32(baseCommitment.previousCommitmentDigestHex),
        logicalTimestampUs: baseCommitment.logicalTimestampUs,
        lsn: baseCommitment.lsn,
        agentId: baseCommitment.agentId,
      },
    });

    const signed: DualSignedCommitmentV3 = {
      commitment: baseCommitment,
      commitmentDigestHex: digest,
      customerSignatureHex: custSig,
      agentSignatureHex: agentSig.toString('hex'),
    };

    const res = await verifyDualSignedCommitment(signed, agentPub);
    expect(res.isValid).toBe(true);
  });
});
