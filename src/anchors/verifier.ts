import { CheckpointStore } from '../checkpoint/types.js';
import { EvmAnchorAdapter } from './evm.js';
import { MultiAnchorConsensusEngine } from './consensus.js';
import { ConsensusPolicy, ConsensusReport } from './types.js';
import { computeCheckpointDigest } from '../checkpoint/anchor.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export interface CrossDomainVerificationReport {
  status:
    | 'AUTHENTIC'
    | 'LOCAL_TAMPERING_DETECTED'
    | 'VAULT_TAMPERING_DETECTED'
    | 'ANCHOR_DIVERGENCE'
    | 'CATASTROPHIC_SPLIT_BRAIN'
    | 'PENDING_ANCHOR'
    | 'STORE_UNAVAILABLE';
  checkpointId: string;
  localDigestHex: string;
  externalVaultDigestHex: string | null;
  blockchainDigestHex: string | null;
  consensusReport?: ConsensusReport | undefined;
  details: string;
}

export class CrossDomainVerifier {
  /**
   * Performs triple-plane verification across database, external vault, and blockchain anchors.
   */
  public static async verifyCrossDomain(
    checkpointId: string,
    observedLocalMerkleRoot: Buffer,
    observedCommitSeq: bigint,
    observedScope: string,
    observedCreatedAtUs: bigint,
    externalVaultStore: CheckpointStore,
    evmAnchors: EvmAnchorAdapter[],
    consensusPolicy?: ConsensusPolicy
  ): Promise<CrossDomainVerificationReport> {
    // 1. Calculate local observed digest
    const localDigest = computeCheckpointDigest({
      checkpointId,
      scope: observedScope,
      commitSeq: observedCommitSeq,
      previousCheckpointId: null,
      merkleRoot: observedLocalMerkleRoot,
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs: observedCreatedAtUs,
      protocolVersion: 3,
    });
    const localDigestHex = localDigest.toString('hex');

    // 2. Fetch external object vault checkpoint
    let externalVaultChk = null;
    try {
      externalVaultChk = await externalVaultStore.get(checkpointId);
    } catch {
      // Handled below
    }

    let externalVaultDigest: Buffer | null = null;
    let externalVaultDigestHex: string | null = null;
    let isVaultMatch = false;

    if (externalVaultChk) {
      externalVaultDigest = computeCheckpointDigest(externalVaultChk);
      externalVaultDigestHex = externalVaultDigest.toString('hex');
      isVaultMatch = timingSafeEqualHashes(localDigest, externalVaultDigest);
    }

    // 3. Query EVM blockchain anchors
    const anchorRecords = [];
    for (const adapter of evmAnchors) {
      try {
        const rec = await adapter.getAnchor(checkpointId);
        anchorRecords.push(rec);
      } catch {
        anchorRecords.push(null);
      }
    }

    const firstValidAnchor = anchorRecords.find((r) => r !== null);
    const blockchainDigestHex = firstValidAnchor ? firstValidAnchor.checkpointDigest.toString('hex') : null;
    const isAnchorMatch = firstValidAnchor
      ? timingSafeEqualHashes(localDigest, firstValidAnchor.checkpointDigest)
      : false;

    const isVaultAnchorMatch =
      externalVaultDigest && firstValidAnchor
        ? timingSafeEqualHashes(externalVaultDigest, firstValidAnchor.checkpointDigest)
        : false;

    // 4. Evaluate multi-anchor consensus if policy provided
    let consensusReport: ConsensusReport | undefined;
    if (consensusPolicy) {
      consensusReport = MultiAnchorConsensusEngine.evaluateConsensus(
        localDigest,
        anchorRecords,
        consensusPolicy
      );
    }

    // 5. Evaluate cross-domain state matrix
    if (isVaultMatch && isAnchorMatch) {
      return {
        status: 'AUTHENTIC',
        checkpointId,
        localDigestHex,
        externalVaultDigestHex,
        blockchainDigestHex,
        consensusReport,
        details: 'Triple-plane cross-domain verification passed: Database, External Vault, and Blockchain in 100% agreement.',
      };
    }

    if (!isVaultMatch && !isAnchorMatch && isVaultAnchorMatch) {
      return {
        status: 'LOCAL_TAMPERING_DETECTED',
        checkpointId,
        localDigestHex,
        externalVaultDigestHex,
        blockchainDigestHex,
        consensusReport,
        details: 'Local state divergence detected: External vault and blockchain anchor agree on authentic historical root.',
      };
    }

    if (!isVaultMatch && isAnchorMatch) {
      return {
        status: 'VAULT_TAMPERING_DETECTED',
        checkpointId,
        localDigestHex,
        externalVaultDigestHex,
        blockchainDigestHex,
        consensusReport,
        details: 'External vault tampering detected: Local database and blockchain anchor agree, but vault record is corrupted.',
      };
    }

    if (isVaultMatch && !isAnchorMatch && firstValidAnchor) {
      return {
        status: 'ANCHOR_DIVERGENCE',
        checkpointId,
        localDigestHex,
        externalVaultDigestHex,
        blockchainDigestHex,
        consensusReport,
        details: 'Blockchain anchor divergence detected: Local database and external vault agree, but blockchain commitment differs.',
      };
    }

    if (!firstValidAnchor) {
      return {
        status: 'PENDING_ANCHOR',
        checkpointId,
        localDigestHex,
        externalVaultDigestHex,
        blockchainDigestHex: null,
        consensusReport,
        details: 'Blockchain anchor is pending confirmation or unreachable.',
      };
    }

    return {
      status: 'CATASTROPHIC_SPLIT_BRAIN',
      checkpointId,
      localDigestHex,
      externalVaultDigestHex,
      blockchainDigestHex,
      consensusReport,
      details: 'Catastrophic cross-domain split-brain: Local database, external vault, and blockchain commitments all disagree.',
    };
  }
}
