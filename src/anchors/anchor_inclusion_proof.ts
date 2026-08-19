import crypto from 'node:crypto';
import {
  MerkleTree,
  MerkleProof,
  computeMerkleLeafHash,
  verifyMerkleProof,
} from '../crypto/merkle.js';
import { CanonicalQuorumCertificate } from '../trust/quorum_certificate.js';
import {
  CanonicalAnchorBatch,
  AnchorSubmissionReceipt,
  computeAnchorBatchDigest,
  AnchorLifecycleState,
} from './batch_anchor.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export interface AnchorInclusionProof {
  proofVersion: number; // 1
  certificateDigestHex: string;
  commitSeq: string; // stringified bigint
  merkleProof: MerkleProof;
  batch: CanonicalAnchorBatch;
  receipt: AnchorSubmissionReceipt;
}

export interface OnChainAnchorRecord {
  checkpointDigestHex: string; // anchorBatchDigestHex stored in contract
  commitSeq: bigint;
  timestampUs: bigint;
  blockNumber: bigint;
  publisher: string;
}

export class AnchorInclusionProofGenerator {
  /**
   * Generates an Anchor Inclusion Proof for a specific Quorum Certificate
   * within an Anchor Batch that has been anchored to blockchain.
   */
  public static generateProof(
    qc: CanonicalQuorumCertificate,
    batchQcs: CanonicalQuorumCertificate[],
    batch: CanonicalAnchorBatch,
    receipt: AnchorSubmissionReceipt
  ): AnchorInclusionProof {
    // Sort batch QCs to match canonical ordering used during batch construction
    const sortedQcs = [...batchQcs].sort((a, b) => (a.commitSeq < b.commitSeq ? -1 : 1));
    const leaves = sortedQcs.map((item) => Buffer.from(item.certificateDigestHex, 'hex'));
    const merkleTree = new MerkleTree(leaves);

    const targetLeaf = Buffer.from(qc.certificateDigestHex, 'hex');
    const leafIndex = leaves.findIndex((l) => timingSafeEqualHashes(l, targetLeaf));

    if (leafIndex === -1) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_INCLUSION_PROOF,
        `Quorum certificate ${qc.certificateDigestHex} is not part of this anchor batch`
      );
    }

    const merkleProof = merkleTree.generateProof(leafIndex);

    return {
      proofVersion: 1,
      certificateDigestHex: qc.certificateDigestHex,
      commitSeq: qc.commitSeq.toString(),
      merkleProof,
      batch,
      receipt,
    };
  }

  /**
   * Verifies an Anchor Inclusion Proof offline (cryptographically)
   * and optionally cross-checks with an on-chain record.
   */
  public static verifyProof(
    proof: AnchorInclusionProof,
    onChainRecord?: OnChainAnchorRecord
  ): {
    isValid: boolean;
    reason?: string;
  } {
    try {
      // 1. Verify Merkle Proof of QC digest in batchRoot
      const rawLeaf = Buffer.from(proof.certificateDigestHex, 'hex');
      const leafHash = computeMerkleLeafHash(rawLeaf);
      const rootBuf = Buffer.from(proof.batch.batchRootHex, 'hex');

      const isMerkleValid = verifyMerkleProof(
        leafHash,
        proof.merkleProof.proof,
        rootBuf,
        proof.merkleProof.leafIndex,
        proof.merkleProof.leafCount
      );
      if (!isMerkleValid) {
        return { isValid: false, reason: 'Invalid Merkle inclusion proof for certificate digest in batch root' };
      }

      // 2. Recompute and verify Anchor Batch Digest
      const computedBatchDigest = computeAnchorBatchDigest(proof.batch);
      const expectedBatchDigest = Buffer.from(proof.batch.anchorBatchDigestHex, 'hex');

      if (!timingSafeEqualHashes(computedBatchDigest, expectedBatchDigest)) {
        return { isValid: false, reason: 'Batch digest mismatch: header parameters do not match anchorBatchDigestHex' };
      }

      // 3. Verify Receipt matches Batch Digest
      if (proof.receipt.batchDigestHex !== proof.batch.anchorBatchDigestHex) {
        return { isValid: false, reason: 'Receipt batchDigestHex does not match batch anchorBatchDigestHex' };
      }

      // 4. If On-Chain record provided, verify chain commitment matches batch digest
      if (onChainRecord) {
        const onChainDigestBuf = Buffer.from(
          onChainRecord.checkpointDigestHex.startsWith('0x')
            ? onChainRecord.checkpointDigestHex.slice(2)
            : onChainRecord.checkpointDigestHex,
          'hex'
        );
        if (!timingSafeEqualHashes(onChainDigestBuf, expectedBatchDigest)) {
          return { isValid: false, reason: 'On-chain recorded digest does not match anchor batch digest' };
        }
      }

      return { isValid: true };
    } catch (err: any) {
      return { isValid: false, reason: `Verification exception: ${err.message}` };
    }
  }
}
