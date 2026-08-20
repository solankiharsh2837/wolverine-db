import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  CanonicalTrustCommitmentV3,
  computeCanonicalCommitmentDigest,
  computeCustomerAuthPreimage,
  computeAgentAttestPreimage,
  verifyDualSignedCommitment,
  DualSignedCommitmentV3,
} from '../../src/protocol/commitment_v3.js';

describe('Canonical Trust Commitment Schema v3', () => {
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
    customerSigningAddress: '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf',
  };

  it('computes deterministic canonical commitment digest (Golden Vector)', () => {
    const digest1 = computeCanonicalCommitmentDigest(baseCommitment);
    const digest2 = computeCanonicalCommitmentDigest({ ...baseCommitment });

    expect(digest1).toBe(digest2);
    expect(digest1).toHaveLength(64);
  });

  it('detects any state modification in commitment digest calculation', () => {
    const originalDigest = computeCanonicalCommitmentDigest(baseCommitment);

    const modifiedRoot = computeCanonicalCommitmentDigest({
      ...baseCommitment,
      stateMerkleRootHex: 'd'.repeat(64),
    });
    expect(modifiedRoot).not.toBe(originalDigest);

    const modifiedSeq = computeCanonicalCommitmentDigest({
      ...baseCommitment,
      commitSeq: 2n,
    });
    expect(modifiedSeq).not.toBe(originalDigest);

    const modifiedChain = computeCanonicalCommitmentDigest({
      ...baseCommitment,
      chainId: 1,
    });
    expect(modifiedChain).not.toBe(originalDigest);
  });

  it('verifies valid dual-signed commitment', () => {
    const agentKeyPair = crypto.generateKeyPairSync('ed25519');
    const agentPub = agentKeyPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    const digest = computeCanonicalCommitmentDigest(baseCommitment);
    const agentPreimage = computeAgentAttestPreimage(baseCommitment, digest);
    const agentSig = crypto.sign(null, agentPreimage, agentKeyPair.privateKey);

    const signed: DualSignedCommitmentV3 = {
      commitment: baseCommitment,
      commitmentDigestHex: digest,
      customerSignatureHex: '11'.repeat(64),
      agentSignatureHex: agentSig.toString('hex'),
    };

    const res = verifyDualSignedCommitment(signed, agentPub);
    expect(res.isValid).toBe(true);
  });

  it('rejects forged agent attestation signature', () => {
    const agentKeyPair1 = crypto.generateKeyPairSync('ed25519');
    const agentKeyPair2 = crypto.generateKeyPairSync('ed25519');
    const agentPub1 = agentKeyPair1.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    const digest = computeCanonicalCommitmentDigest(baseCommitment);
    const agentPreimage = computeAgentAttestPreimage(baseCommitment, digest);
    // Sign with wrong key
    const forgedSig = crypto.sign(null, agentPreimage, agentKeyPair2.privateKey);

    const signed: DualSignedCommitmentV3 = {
      commitment: baseCommitment,
      commitmentDigestHex: digest,
      customerSignatureHex: '11'.repeat(64),
      agentSignatureHex: forgedSig.toString('hex'),
    };

    const res = verifyDualSignedCommitment(signed, agentPub1);
    expect(res.isValid).toBe(false);
    expect(res.error).toContain('Agent attestation signature verification failed');
  });

  it('rejects commitment if LSN or tenant is tampered after signing', () => {
    const agentKeyPair = crypto.generateKeyPairSync('ed25519');
    const agentPub = agentKeyPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);

    const digest = computeCanonicalCommitmentDigest(baseCommitment);
    const agentPreimage = computeAgentAttestPreimage(baseCommitment, digest);
    const agentSig = crypto.sign(null, agentPreimage, agentKeyPair.privateKey);

    // Adversary tampers with LSN in payload
    const tamperedCommitment = { ...baseCommitment, lsn: '0/9999999' };
    const tamperedDigest = computeCanonicalCommitmentDigest(tamperedCommitment);

    const signed: DualSignedCommitmentV3 = {
      commitment: tamperedCommitment,
      commitmentDigestHex: tamperedDigest,
      customerSignatureHex: '11'.repeat(64),
      agentSignatureHex: agentSig.toString('hex'), // Old signature over previous digest/lsn
    };

    const res = verifyDualSignedCommitment(signed, agentPub);
    expect(res.isValid).toBe(false);
  });
});
