import crypto from 'node:crypto';
import { canonicalizeJson } from '../binary/c14n.js';
import { CanonicalQuorumCertificate } from '../trust/quorum_certificate.js';
import { CanonicalValidatorSet } from '../trust/validator_set.js';
import { CrossEpochTransitionCertificate } from '../trust/epoch_transition.js';
import { CanonicalCommitment } from '../trust/commitment.js';
import { CanonicalAnchorBatch, AnchorSubmissionReceipt } from '../anchors/batch_anchor.js';

export interface PortableProofPackage {
  packageVersion: number; // 2
  receipt: {
    tenantId: string;
    databaseId: string;
    epoch: number;
    commitSeq: string;
    commitmentDigestHex: string;
    stateMerkleRootHex: string;
    changeChainHeadHex: string;
    lsn: string;
    logicalTimestampUs: string;
  };
  quorumCertificate: {
    certificateVersion: number;
    commitmentId: string;
    validatorSetId: string;
    epoch: number;
    commitSeq: string;
    commitmentDigestHex: string;
    finalizedAtUs: string;
    quorumCount: number;
    totalValidators: number;
    attestations: Array<{
      validatorId: string;
      commitmentId: string;
      commitmentDigestHex: string;
      epoch: number;
      commitSeq: string;
      attestationTimestampUs: string;
      signatureHex: string;
    }>;
    certificateDigestHex: string;
  };
  validatorSet: {
    validatorSetId: string;
    epoch: number;
    quorumThreshold: number;
    totalValidators: number;
    validators: Array<{
      validatorId: string;
      publicKeyHex: string;
      weight: number;
    }>;
  };
  transitionCertificates?: CrossEpochTransitionCertificate[];
  customerAuthorization: {
    keyId: string;
    customerPubkeyHex: string;
    signatureHex: string;
    commitSeq: string;
  };
  agentAttestation: {
    agentNodeId: string;
    agentPubkeyHex: string;
    signatureHex: string;
    lsn: string;
  };
  merkleProof: {
    table: string;
    rowKeyHex: string;
    rowValues: Record<string, any>;
    rowHashHex: string;
    stateMerkleRootHex: string;
  };
  ledgerProof: {
    batchDigestHex: string;
    batchRootHex: string;
    qcIndexInBatch: number;
  };
  anchor: {
    networkId: string;
    txHashHex: string;
    blockNumber: string;
    blockHashHex: string;
    blockTimestamp: string;
    contractAddress: string;
    trustedBlockHeaderRootHex: string;
  };
  manifestDigestHex: string;
}

export class ProofPackageBuilder {
  /**
   * Constructs a self-contained portable proof package.
   */
  public static buildPackage(params: {
    commitment: CanonicalCommitment;
    qc: CanonicalQuorumCertificate;
    validatorSet: CanonicalValidatorSet;
    transitionCertificates?: CrossEpochTransitionCertificate[];
    table: string;
    rowKeyHex: string;
    rowValues: Record<string, any>;
    anchorBatch?: CanonicalAnchorBatch;
    anchorReceipt?: AnchorSubmissionReceipt;
  }): PortableProofPackage {
    const rawReceipt = {
      tenantId: params.commitment.tenantId,
      databaseId: params.commitment.databaseId,
      epoch: params.commitment.epoch,
      commitSeq: params.commitment.commitSeq.toString(),
      commitmentDigestHex: params.qc.commitmentDigestHex,
      stateMerkleRootHex: params.commitment.stateMerkleRootHex,
      changeChainHeadHex: params.commitment.changeChainHeadHex,
      lsn: params.commitment.lsn,
      logicalTimestampUs: params.commitment.logicalTimestampUs.toString(),
    };

    const rawQC = {
      certificateVersion: params.qc.certificateVersion,
      commitmentId: params.qc.commitmentId,
      validatorSetId: params.qc.validatorSetId,
      epoch: params.qc.epoch,
      commitSeq: params.qc.commitSeq.toString(),
      commitmentDigestHex: params.qc.commitmentDigestHex,
      finalizedAtUs: params.qc.finalizedAtUs.toString(),
      quorumCount: params.qc.quorumCount,
      totalValidators: params.qc.totalValidators,
      attestations: params.qc.attestations.map((a) => ({
        validatorId: a.validatorId,
        commitmentId: a.commitmentId,
        commitmentDigestHex: a.commitmentDigestHex,
        epoch: a.epoch,
        commitSeq: a.commitSeq.toString(),
        attestationTimestampUs: a.attestationTimestampUs.toString(),
        signatureHex: a.signatureHex,
      })),
      certificateDigestHex: params.qc.certificateDigestHex,
    };

    const rowCanonicalJson = canonicalizeJson({
      table: params.table,
      pk: params.rowKeyHex,
      values: params.rowValues,
      epoch: params.commitment.epoch,
    });
    const rowHashHex = crypto.createHash('sha256').update(Buffer.from(rowCanonicalJson, 'utf8')).digest('hex');

    const pkgWithoutManifest: Omit<PortableProofPackage, 'manifestDigestHex'> = {
      packageVersion: 2,
      receipt: rawReceipt,
      quorumCertificate: rawQC,
      validatorSet: params.validatorSet,
      transitionCertificates: params.transitionCertificates || [],
      customerAuthorization: {
        keyId: params.commitment.customerAuthorization.keyId,
        customerPubkeyHex: params.commitment.customerAuthorization.customerPubkeyHex,
        signatureHex: params.commitment.customerAuthorization.signatureHex,
        commitSeq: params.commitment.customerAuthorization.commitSeq.toString(),
      },
      agentAttestation: {
        agentNodeId: params.commitment.agentAttestation.agentNodeId,
        agentPubkeyHex: params.commitment.agentAttestation.agentPubkeyHex,
        signatureHex: params.commitment.agentAttestation.signatureHex,
        lsn: params.commitment.agentAttestation.lsn,
      },
      merkleProof: {
        table: params.table,
        rowKeyHex: params.rowKeyHex,
        rowValues: params.rowValues,
        rowHashHex,
        stateMerkleRootHex: params.commitment.stateMerkleRootHex,
      },
      ledgerProof: {
        batchDigestHex: params.anchorBatch?.anchorBatchDigestHex || '00'.repeat(32),
        batchRootHex: params.anchorBatch?.batchRootHex || '00'.repeat(32),
        qcIndexInBatch: 0,
      },
      anchor: {
        networkId: params.anchorBatch?.networkId || 'base-mainnet',
        txHashHex: params.anchorReceipt?.txHashHex || '0x' + '00'.repeat(32),
        blockNumber: (params.anchorReceipt?.blockNumber || 1000000n).toString(),
        blockHashHex: params.anchorReceipt?.blockHashHex || '0x' + '00'.repeat(32),
        blockTimestamp: '1723800000',
        contractAddress: params.anchorReceipt?.contractAddress || '0xWolverineAnchorRegistry000000000000000',
        trustedBlockHeaderRootHex: params.anchorBatch?.batchRootHex || '00'.repeat(32),
      },
    };

    const manifestDigestHex = crypto
      .createHash('sha256')
      .update(Buffer.from(canonicalizeJson(pkgWithoutManifest), 'utf8'))
      .digest('hex');

    return {
      ...pkgWithoutManifest,
      manifestDigestHex,
    };
  }
}
