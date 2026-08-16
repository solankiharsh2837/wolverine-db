import crypto from 'node:crypto';
import { TrustCommitment, QuorumCertificate } from './types.js';
import { encodeProtocolTuple } from '../crypto/canonical.js';
import { MerkleTree } from '../crypto/merkle.js';

export interface WolverineTrustBlockHeader {
  networkId: string;
  epoch: number;
  blockHeight: bigint;
  previousBlockHash: Buffer;
  timestampUs: bigint;
  transactionsRoot: Buffer;
  stateRoot: Buffer;
  validatorSetHash: Buffer;
}

export interface WolverineTrustBlock extends WolverineTrustBlockHeader {
  commitments: TrustCommitment[];
  quorumCertificate: QuorumCertificate;
  blockHash: Buffer;
}

export function computeValidatorSetHash(validatorPublicKeys: Buffer[]): Buffer {
  const sorted = [...validatorPublicKeys].sort((a, b) => Buffer.compare(a, b));
  return crypto.createHash('sha256').update(Buffer.concat(sorted)).digest();
}

export function computeTransactionsRoot(commitments: TrustCommitment[]): Buffer {
  if (commitments.length === 0) {
    return Buffer.alloc(32, 0);
  }
  const digests = commitments.map((c) => c.commitmentDigest);
  const tree = new MerkleTree(digests);
  return tree.root;
}

export function computeTrustBlockHash(header: WolverineTrustBlockHeader): Buffer {
  const preimage = encodeProtocolTuple('WDB:TRUST_BLOCK:v1:', [
    header.networkId,
    header.epoch,
    header.blockHeight,
    header.previousBlockHash,
    header.timestampUs,
    header.transactionsRoot,
    header.stateRoot,
    header.validatorSetHash,
  ]);

  return crypto.createHash('sha256').update(preimage).digest();
}

export class TrustBlockBuilder {
  public static buildBlock(params: {
    networkId: string;
    epoch: number;
    blockHeight: bigint;
    previousBlockHash: Buffer;
    timestampUs: bigint;
    commitments: TrustCommitment[];
    stateRoot: Buffer;
    validatorPublicKeys: Buffer[];
    quorumCertificate: QuorumCertificate;
  }): WolverineTrustBlock {
    const transactionsRoot = computeTransactionsRoot(params.commitments);
    const validatorSetHash = computeValidatorSetHash(params.validatorPublicKeys);

    const header: WolverineTrustBlockHeader = {
      networkId: params.networkId,
      epoch: params.epoch,
      blockHeight: params.blockHeight,
      previousBlockHash: params.previousBlockHash,
      timestampUs: params.timestampUs,
      transactionsRoot,
      stateRoot: params.stateRoot,
      validatorSetHash,
    };

    const blockHash = computeTrustBlockHash(header);

    return {
      ...header,
      commitments: params.commitments,
      quorumCertificate: params.quorumCertificate,
      blockHash,
    };
  }
}
