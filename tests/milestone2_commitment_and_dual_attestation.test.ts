import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  CanonicalCommitment,
  computeCanonicalCommitmentDigest,
  computeAgentAttestationDigest,
  computeCustomerAuthorizationDigest,
  verifyDualAttestation,
  SoftwareCustomerSigner,
} from '../src/index.js';

describe('Milestone 2.1 & 2.2 — Canonical Commitment Digest & Dual Attestation', () => {
  const agentKeypair = crypto.generateKeyPairSync('ed25519');
  const customerKeypair = crypto.generateKeyPairSync('ed25519');

  const agentPubkey = agentKeypair.publicKey.export({ format: 'der', type: 'spki' });
  const customerPubkey = customerKeypair.publicKey.export({ format: 'der', type: 'spki' });

  function createSignedCommitment(seq: bigint = 1n, lsn: string = '0/1600100'): CanonicalCommitment {
    const unsigned = {
      commitmentId: `cmt-${seq}`,
      tenantId: 'enterprise_bank',
      databaseId: 'core_ledger',
      epoch: 1,
      commitSeq: seq,
      checkpointDigestHex: '8e4f2728690f5b33a7e61d15881334c705770f18450ecdc1c3b77f02f3df6024',
      stateMerkleRootHex: '5a1f8b4c092288337711eeddaabbccddeeff00112233445566778899aabbccdd',
      changeChainHeadHex: 'f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f',
      logicalTimestampUs: 1723800000000000n,
      lsn,
      previousCommitmentDigestHex: '0000000000000000000000000000000000000000000000000000000000000000',
    };

    const commitmentDigest = computeCanonicalCommitmentDigest(unsigned);

    // 1. Agent signs (Digest || LSN)
    const agentDigest = computeAgentAttestationDigest(commitmentDigest, lsn);
    const agentSig = crypto.sign(null, agentDigest, agentKeypair.privateKey);

    // 2. Customer signs (Digest || commitSeq)
    const customerDigest = computeCustomerAuthorizationDigest(commitmentDigest, seq);
    const customerSig = crypto.sign(null, customerDigest, customerKeypair.privateKey);

    return {
      ...unsigned,
      agentAttestation: {
        agentNodeId: 'enclave-node-01',
        agentPubkeyHex: agentPubkey.toString('hex'),
        signatureHex: agentSig.toString('hex'),
        lsn,
      },
      customerAuthorization: {
        keyId: 'arn:aws:kms:us-east-1:112233445566:key/cust-prod',
        customerPubkeyHex: customerPubkey.toString('hex'),
        signatureHex: customerSig.toString('hex'),
        commitSeq: seq,
      },
    };
  }

  it('1. Canonical Commitment Digest: independent validators derive identical D_n from canonical JSON', () => {
    const cmt1 = createSignedCommitment(1842n);
    const digest1 = computeCanonicalCommitmentDigest(cmt1);

    expect(digest1.length).toBe(32);

    // Reconstruct with shuffled key ordering in caller object
    const cmtShuffled = {
      previousCommitmentDigestHex: cmt1.previousCommitmentDigestHex,
      lsn: cmt1.lsn,
      logicalTimestampUs: cmt1.logicalTimestampUs,
      changeChainHeadHex: cmt1.changeChainHeadHex,
      stateMerkleRootHex: cmt1.stateMerkleRootHex,
      checkpointDigestHex: cmt1.checkpointDigestHex,
      commitSeq: cmt1.commitSeq,
      epoch: cmt1.epoch,
      databaseId: cmt1.databaseId,
      tenantId: cmt1.tenantId,
      commitmentId: cmt1.commitmentId,
    };

    const digest2 = computeCanonicalCommitmentDigest(cmtShuffled);
    expect(digest1.toString('hex')).toBe(digest2.toString('hex'));
  });

  it('2. Dual Attestation Verification: passes when both agent and customer signatures are valid', () => {
    const commitment = createSignedCommitment(1n);
    const result = verifyDualAttestation(commitment, agentPubkey, customerPubkey);

    expect(result.valid).toBe(true);
    expect(result.commitmentDigest.length).toBe(32);
  });

  it('3. Dual Attestation Tamper Defense: rejects if agent signature is forged or corrupted', () => {
    const commitment = createSignedCommitment(1n);
    // Corrupt agent signature
    commitment.agentAttestation.signatureHex = Buffer.alloc(64, 0xaa).toString('hex');

    expect(() => verifyDualAttestation(commitment, agentPubkey, customerPubkey)).toThrowError(
      /Agent enclave attestation signature verification failed/
    );
  });

  it('4. Dual Attestation Tamper Defense: rejects if customer signature is forged or corrupted', () => {
    const commitment = createSignedCommitment(1n);
    // Corrupt customer signature
    commitment.customerAuthorization.signatureHex = Buffer.alloc(64, 0xbb).toString('hex');

    expect(() => verifyDualAttestation(commitment, agentPubkey, customerPubkey)).toThrowError(
      /Customer root authorization signature verification failed/
    );
  });

  it('5. Dual Attestation Authority Separation: SoftwareCustomerSigner generates authentic authorization', async () => {
    const signer = new SoftwareCustomerSigner('cust-local-key', customerKeypair.privateKey);
    const unsigned = {
      commitmentId: 'cmt-100',
      tenantId: 'fintech_co',
      databaseId: 'db_ledger',
      epoch: 1,
      commitSeq: 100n,
      checkpointDigestHex: '11223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff',
      stateMerkleRootHex: 'aabbccddeeff001122334455667788990011223344556677889900aabbccddeeff',
      changeChainHeadHex: '0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff',
      logicalTimestampUs: 1723800000000000n,
      lsn: '0/2000000',
      previousCommitmentDigestHex: '0000000000000000000000000000000000000000000000000000000000000000',
    };
    const cmtDigest = computeCanonicalCommitmentDigest(unsigned);
    const signature = await signer.signCommitment(cmtDigest, 100n);

    expect(signature.length).toBe(64);

    const agentDigest = computeAgentAttestationDigest(cmtDigest, '0/2000000');
    const agentSig = crypto.sign(null, agentDigest, agentKeypair.privateKey);

    const fullCommitment: CanonicalCommitment = {
      ...unsigned,
      agentAttestation: {
        agentNodeId: 'node-01',
        agentPubkeyHex: agentPubkey.toString('hex'),
        signatureHex: agentSig.toString('hex'),
        lsn: '0/2000000',
      },
      customerAuthorization: {
        keyId: 'cust-local-key',
        customerPubkeyHex: signer.publicKey.toString('hex'),
        signatureHex: signature.toString('hex'),
        commitSeq: 100n,
      },
    };

    const res = verifyDualAttestation(fullCommitment, agentPubkey, signer.publicKey);
    expect(res.valid).toBe(true);
  });
});
