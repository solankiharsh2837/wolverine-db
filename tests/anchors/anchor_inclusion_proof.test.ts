import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  BatchAnchorManager,
  CanonicalQuorumCertificate,
  AnchorLifecycleState,
} from '../../src/index.js';
import {
  AnchorInclusionProofGenerator,
  OnChainAnchorRecord,
} from '../../src/anchors/anchor_inclusion_proof.js';

describe('Milestone 2 — Anchor Inclusion Proof Generation & Verification', () => {
  const createMockQC = (seq: bigint): CanonicalQuorumCertificate => {
    const certDigest = crypto.createHash('sha256').update(`qc_payload_${seq}`).digest('hex');
    const commitmentDigest = crypto.createHash('sha256').update(`commit_${seq}`).digest('hex');
    return {
      certificateVersion: 2,
      tenantId: 'tenant_anchor_01',
      databaseId: 'db_anchor_01',
      commitSeq: seq,
      checkpointDigestHex: crypto.createHash('sha256').update(`chk_${seq}`).digest('hex'),
      stateMerkleRootHex: crypto.createHash('sha256').update(`root_${seq}`).digest('hex'),
      hashChainDigestHex: crypto.createHash('sha256').update(`chain_${seq}`).digest('hex'),
      lsn: `0/${seq}00000`,
      timestampUs: BigInt(Date.now()) * 1000n,
      epoch: 1,
      validatorSetId: 'valset-genesis',
      quorumCount: 5,
      totalValidators: 5,
      validatorSignatures: [
        { validatorId: 'v1', signatureHex: 'aa' },
        { validatorId: 'v2', signatureHex: 'bb' },
        { validatorId: 'v3', signatureHex: 'cc' },
        { validatorId: 'v4', signatureHex: 'dd' },
        { validatorId: 'v5', signatureHex: 'ee' },
      ],
      commitmentDigestHex: commitmentDigest,
      certificateDigestHex: certDigest,
    };
  };

  it('generates valid cryptographic inclusion proof linking QC to batch root and on-chain record', async () => {
    const qcs = [createMockQC(1n), createMockQC(2n), createMockQC(3n), createMockQC(4n)];
    const manager = new BatchAnchorManager('base-mainnet', 'valset-genesis', 1, 4);

    let batch = null;
    for (const qc of qcs) {
      batch = manager.enqueueQuorumCertificate(qc);
    }
    expect(batch).not.toBeNull();

    const receipt = {
      batchDigestHex: batch!.anchorBatchDigestHex,
      txHashHex: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      blockNumber: 12345678n,
      blockHashHex: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
      contractAddress: '0x1234567890123456789012345678901234567890',
      submittedAtUs: BigInt(Date.now()) * 1000n,
      state: AnchorLifecycleState.FINALIZED,
      confirmations: 64,
    };

    // Generate proof for QC #3
    const proof = AnchorInclusionProofGenerator.generateProof(qcs[2]!, qcs, batch!, receipt);

    expect(proof.commitSeq).toBe('3');
    expect(proof.certificateDigestHex).toBe(qcs[2]!.certificateDigestHex);

    // Verify proof offline
    const offlineVerification = AnchorInclusionProofGenerator.verifyProof(proof);
    expect(offlineVerification.isValid).toBe(true);

    // Verify proof with matching on-chain record
    const onChainRecord: OnChainAnchorRecord = {
      checkpointDigestHex: batch!.anchorBatchDigestHex,
      commitSeq: batch!.endLedgerSeq,
      timestampUs: batch!.createdAtUs,
      blockNumber: 12345678n,
      publisher: '0x1234567890123456789012345678901234567890',
    };

    const onChainVerification = AnchorInclusionProofGenerator.verifyProof(proof, onChainRecord);
    expect(onChainVerification.isValid).toBe(true);
  });

  it('rejects tampered inclusion proof or on-chain digest mismatch', async () => {
    const qcs = [createMockQC(1n), createMockQC(2n)];
    const manager = new BatchAnchorManager('base-mainnet', 'valset-genesis', 1, 2);

    let batch = null;
    for (const qc of qcs) {
      batch = manager.enqueueQuorumCertificate(qc);
    }

    const receipt = {
      batchDigestHex: batch!.anchorBatchDigestHex,
      txHashHex: '0x1234',
      blockNumber: 100n,
      blockHashHex: '0x5678',
      contractAddress: '0x0000',
      submittedAtUs: 1000n,
      state: AnchorLifecycleState.FINALIZED,
      confirmations: 64,
    };

    const proof = AnchorInclusionProofGenerator.generateProof(qcs[0]!, qcs, batch!, receipt);

    // Tamper with certificate digest in proof
    const tamperedProof = {
      ...proof,
      certificateDigestHex: crypto.createHash('sha256').update('tampered').digest('hex'),
    };

    const failedVerification = AnchorInclusionProofGenerator.verifyProof(tamperedProof);
    expect(failedVerification.isValid).toBe(false);

    // Mismatched on-chain digest
    const wrongOnChainRecord: OnChainAnchorRecord = {
      checkpointDigestHex: crypto.createHash('sha256').update('different_digest').digest('hex'),
      commitSeq: 2n,
      timestampUs: 1000n,
      blockNumber: 100n,
      publisher: '0x0000',
    };

    const onChainMismatch = AnchorInclusionProofGenerator.verifyProof(proof, wrongOnChainRecord);
    expect(onChainMismatch.isValid).toBe(false);
  });
});
