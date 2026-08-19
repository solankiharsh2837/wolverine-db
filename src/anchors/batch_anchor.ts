import crypto from 'node:crypto';
import { canonicalizeJson } from '../binary/c14n.js';
import { MerkleTree } from '../crypto/merkle.js';
import { CanonicalQuorumCertificate } from '../trust/quorum_certificate.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export enum AnchorLifecycleState {
  PENDING = 'PENDING',
  SUBMITTED = 'SUBMITTED',
  INCLUDED = 'INCLUDED',
  CONFIRMING = 'CONFIRMING',
  FINALIZED = 'FINALIZED',
  REORG_DETECTED = 'REORG_DETECTED',
  REANCHOR_REQUIRED = 'REANCHOR_REQUIRED',
}

export interface CanonicalAnchorBatch {
  networkId: string; // e.g. 'base-mainnet' | 'ethereum-mainnet' | 'base-sepolia'
  epoch: number;
  startLedgerSeq: bigint;
  endLedgerSeq: bigint;
  ledgerStateRootHex: string;
  previousAnchorRootHex: string;
  batchRootHex: string;
  validatorSetId: string;
  anchorVersion: number; // 2
  createdAtUs: bigint;
  anchorBatchDigestHex: string;
}

export interface AnchorSubmissionReceipt {
  batchDigestHex: string;
  txHashHex: string;
  blockNumber: bigint;
  blockHashHex: string;
  contractAddress: string;
  submittedAtUs: bigint;
  state: AnchorLifecycleState;
  confirmations: number;
}

export function computeAnchorBatchDigest(
  batch: Omit<CanonicalAnchorBatch, 'anchorBatchDigestHex'>
): Buffer {
  const prevRootBuf = Buffer.from(batch.previousAnchorRootHex, 'hex');
  const ledgerRootBuf = Buffer.from(batch.ledgerStateRootHex, 'hex');

  const startSeqBuf = Buffer.alloc(8);
  startSeqBuf.writeBigUInt64BE(batch.startLedgerSeq, 0);

  const endSeqBuf = Buffer.alloc(8);
  endSeqBuf.writeBigUInt64BE(batch.endLedgerSeq, 0);

  const epochBuf = Buffer.alloc(4);
  epochBuf.writeUInt32BE(batch.epoch, 0);

  const preimage = Buffer.concat([
    Buffer.from('WDB:ANCHOR_BATCH:v2:', 'utf8'),
    prevRootBuf,
    ledgerRootBuf,
    startSeqBuf,
    endSeqBuf,
    epochBuf,
    Buffer.from(batch.validatorSetId, 'utf8'),
  ]);

  return crypto.createHash('sha256').update(preimage).digest();
}

export interface BlockchainAnchorProvider {
  submitAnchor(
    batch: CanonicalAnchorBatch
  ): Promise<{ txHashHex: string; blockNumber: bigint; blockHashHex: string }>;
  checkStatus(txHashHex: string): Promise<{ confirmed: boolean; reorged: boolean; confirmations: number }>;
}

export class BatchAnchorManager {
  private networkId: string;
  private validatorSetId: string;
  private epoch: number;
  private provider?: BlockchainAnchorProvider;
  private batchSize: number;
  private pendingQCs: CanonicalQuorumCertificate[] = [];
  private lastAnchorBatchDigest: Buffer = Buffer.alloc(32, 0);
  private lastAnchoredSeq: bigint = 0n;
  private anchors: CanonicalAnchorBatch[] = [];
  private submissions = new Map<string, AnchorSubmissionReceipt>();

  constructor(
    networkId: string,
    validatorSetId: string,
    epoch: number = 1,
    batchSize: number = 10,
    provider?: BlockchainAnchorProvider
  ) {
    this.networkId = networkId;
    this.validatorSetId = validatorSetId;
    this.epoch = epoch;
    this.batchSize = batchSize;
    this.provider = provider;
  }

  public setProvider(provider: BlockchainAnchorProvider): void {
    this.provider = provider;
  }

  public get pendingCount(): number {
    return this.pendingQCs.length;
  }

  public get totalAnchors(): number {
    return this.anchors.length;
  }

  /**
   * Queues a finalized Quorum Certificate into the batch anchor pipeline.
   */
  public enqueueQuorumCertificate(qc: CanonicalQuorumCertificate): CanonicalAnchorBatch | null {
    this.pendingQCs.push(qc);

    if (this.pendingQCs.length >= this.batchSize) {
      return this.flushBatch();
    }
    return null;
  }

  /**
   * Flushes current pending QCs into a canonical Anchor Batch.
   */
  public flushBatch(): CanonicalAnchorBatch | null {
    if (this.pendingQCs.length === 0) return null;

    const qcsToAnchor = [...this.pendingQCs];
    this.pendingQCs = [];

    // Sort by sequence strictly
    qcsToAnchor.sort((a, b) => (a.commitSeq < b.commitSeq ? -1 : 1));

    const startSeq = qcsToAnchor[0]!.commitSeq;
    const endSeq = qcsToAnchor[qcsToAnchor.length - 1]!.commitSeq;

    // Invariant: startSeq must be contiguous with lastAnchoredSeq (unless first batch)
    if (this.lastAnchoredSeq > 0n && startSeq !== this.lastAnchoredSeq + 1n) {
      throw new WolverineError(
        WolverineErrorCode.SEQUENCE_GAP_DETECTED,
        `Anchor batch sequence discontinuity: expected startSeq ${this.lastAnchoredSeq + 1n}, observed ${startSeq}`
      );
    }

    // Build Merkle Tree over QC digests
    const leaves = qcsToAnchor.map((qc) => Buffer.from(qc.certificateDigestHex, 'hex'));
    const merkleTree = new MerkleTree(leaves);
    const ledgerStateRootHex = merkleTree.root.toString('hex');

    const partial = {
      networkId: this.networkId,
      epoch: this.epoch,
      startLedgerSeq: startSeq,
      endLedgerSeq: endSeq,
      ledgerStateRootHex,
      previousAnchorRootHex: this.lastAnchorBatchDigest.toString('hex'),
      batchRootHex: ledgerStateRootHex,
      validatorSetId: this.validatorSetId,
      anchorVersion: 2,
      createdAtUs: BigInt(Date.now()) * 1000n,
    };

    const digest = computeAnchorBatchDigest(partial);
    const fullBatch: CanonicalAnchorBatch = {
      ...partial,
      anchorBatchDigestHex: digest.toString('hex'),
    };

    this.anchors.push(fullBatch);
    this.lastAnchorBatchDigest = digest;
    this.lastAnchoredSeq = endSeq;

    return fullBatch;
  }

  /**
   * Submits an anchor batch to the blockchain asynchronously.
   * NEVER blocks Plane 1 or Plane 2 consensus on failure.
   */
  public async submitToBlockchain(batch?: CanonicalAnchorBatch | null): Promise<AnchorSubmissionReceipt | null> {
    if (!this.provider || !batch) {
      return null;
    }

    try {
      const res = await this.provider.submitAnchor(batch);
      const receipt: AnchorSubmissionReceipt = {
        batchDigestHex: batch.anchorBatchDigestHex,
        txHashHex: res.txHashHex,
        blockNumber: res.blockNumber,
        blockHashHex: res.blockHashHex,
        contractAddress: '0xWolverineAnchorRegistry000000000000000',
        submittedAtUs: BigInt(Date.now()) * 1000n,
        state: AnchorLifecycleState.INCLUDED,
        confirmations: 1,
      };

      this.submissions.set(batch.anchorBatchDigestHex, receipt);
      return receipt;
    } catch {
      // PLANE 3 FAILURE ISOLATION: Plane 3 failure does NOT halt Plane 2
      const pendingReceipt: AnchorSubmissionReceipt = {
        batchDigestHex: batch.anchorBatchDigestHex,
        txHashHex: '',
        blockNumber: 0n,
        blockHashHex: '',
        contractAddress: '',
        submittedAtUs: BigInt(Date.now()) * 1000n,
        state: AnchorLifecycleState.PENDING,
        confirmations: 0,
      };
      this.submissions.set(batch.anchorBatchDigestHex, pendingReceipt);
      return pendingReceipt;
    }
  }

  public getSubmission(batchDigestHex: string): AnchorSubmissionReceipt | undefined {
    return this.submissions.get(batchDigestHex);
  }

  public getAnchors(): CanonicalAnchorBatch[] {
    return [...this.anchors];
  }
}
