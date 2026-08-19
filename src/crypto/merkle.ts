import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { sha256, timingSafeEqualHashes } from './hash.js';

export const EMPTY_TREE_ROOT = sha256(Buffer.from('WDB:EMPTY_ROOT:v2:', 'utf8'));

export interface MerkleProofStep {
  side: 0 | 1; // 0 = sibling on left, 1 = sibling on right
  siblingHash: Buffer; // 32 bytes
}

export interface MerkleProof {
  leafHash: Buffer;
  leafIndex: number;
  leafCount: number;
  proof: MerkleProofStep[];
  root: Buffer;
}

/**
 * Computes Merkle leaf hash: SHA256("WDB:LEAF:v2:" || u32be(len) || leaf_bytes)
 */
export function computeMerkleLeafHash(leafBytes: Buffer): Buffer {
  const domain = Buffer.from('WDB:LEAF:v2:', 'utf8');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(leafBytes.length, 0);

  return sha256(Buffer.concat([domain, lenBuf, leafBytes]));
}

/**
 * Computes Merkle internal node hash: SHA256("WDB:NODE:v2:" || left || right)
 */
export function computeMerkleNodeHash(leftHash: Buffer, rightHash: Buffer): Buffer {
  if (leftHash.length !== 32 || rightHash.length !== 32) {
    throw new WolverineError(
      WolverineErrorCode.MERKLE_ROOT_MISMATCH,
      'Merkle node left and right hashes must be 32 bytes each'
    );
  }

  const domain = Buffer.from('WDB:NODE:v2:', 'utf8');
  return sha256(Buffer.concat([domain, leftHash, rightHash]));
}

/**
 * Calculates largest power of 2 less than n (RFC 6962 split point).
 */
export function largestPowerOfTwoLessThan(n: number): number {
  if (n <= 1) return 0;
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

/**
 * Computes RFC 6962 tree hash over a sub-array of leaves.
 */
function computeSubtreeRoot(leaves: Buffer[], start: number, end: number): Buffer {
  const count = end - start;
  if (count === 0) return EMPTY_TREE_ROOT;
  if (count === 1) return leaves[start]!;

  const k = largestPowerOfTwoLessThan(count);
  const leftRoot = computeSubtreeRoot(leaves, start, start + k);
  const rightRoot = computeSubtreeRoot(leaves, start + k, end);

  return computeMerkleNodeHash(leftRoot, rightRoot);
}

/**
 * Generates RFC 6962 inclusion proof steps for a leaf index.
 */
function generateSubtreeProof(
  leaves: Buffer[],
  start: number,
  end: number,
  targetIndex: number,
  proof: MerkleProofStep[]
): void {
  const count = end - start;
  if (count <= 1) return;

  const k = largestPowerOfTwoLessThan(count);
  const split = start + k;

  if (targetIndex < split) {
    // Target is in left subtree, right subtree root is sibling on right (side = 1)
    const rightSibling = computeSubtreeRoot(leaves, split, end);
    proof.push({ side: 1, siblingHash: rightSibling });
    generateSubtreeProof(leaves, start, split, targetIndex, proof);
  } else {
    // Target is in right subtree, left subtree root is sibling on left (side = 0)
    const leftSibling = computeSubtreeRoot(leaves, start, split);
    proof.push({ side: 0, siblingHash: leftSibling });
    generateSubtreeProof(leaves, split, end, targetIndex, proof);
  }
}

export class MerkleTree {
  public readonly leaves: Buffer[];
  public readonly root: Buffer;
  public readonly leafCount: number;

  constructor(leafPayloads: Buffer[]) {
    if (!leafPayloads || leafPayloads.length === 0) {
      this.leaves = [];
      this.leafCount = 0;
      this.root = EMPTY_TREE_ROOT;
      return;
    }

    this.leaves = leafPayloads.map((payload) => computeMerkleLeafHash(payload));
    this.leafCount = this.leaves.length;
    this.root = computeSubtreeRoot(this.leaves, 0, this.leafCount);
  }

  /**
   * Generates an RFC 6962 inclusion proof for a given leaf index.
   */
  public generateProof(leafIndex: number): MerkleProof {
    if (leafIndex < 0 || leafIndex >= this.leafCount) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_INCLUSION_PROOF,
        `Leaf index ${leafIndex} out of bounds (0 to ${this.leafCount - 1})`
      );
    }

    const proofSteps: MerkleProofStep[] = [];
    generateSubtreeProof(this.leaves, 0, this.leafCount, leafIndex, proofSteps);

    // Proof steps are generated top-down; reverse them so verification proceeds bottom-up
    proofSteps.reverse();

    return {
      leafHash: this.leaves[leafIndex]!,
      leafIndex,
      leafCount: this.leafCount,
      proof: proofSteps,
      root: this.root,
    };
  }
}

/**
 * Verifies an RFC 6962 Merkle inclusion proof in constant time with leafCount bounds checking.
 */
export function verifyMerkleProof(
  leafHash: Buffer,
  proofSteps: MerkleProofStep[],
  claimedRoot: Buffer,
  leafIndex?: number,
  leafCount?: number
): boolean {
  if (leafHash.length !== 32 || claimedRoot.length !== 32) {
    return false;
  }

  // Bounds validation if leafIndex and leafCount are specified
  if (leafIndex !== undefined && leafCount !== undefined) {
    if (leafIndex < 0 || leafIndex >= leafCount) {
      return false;
    }
  }

  let currentHash = leafHash;

  for (const step of proofSteps) {
    if (step.siblingHash.length !== 32) {
      return false;
    }

    if (step.side === 0) {
      // Sibling is on left
      currentHash = computeMerkleNodeHash(step.siblingHash, currentHash);
    } else if (step.side === 1) {
      // Sibling is on right
      currentHash = computeMerkleNodeHash(currentHash, step.siblingHash);
    } else {
      return false;
    }
  }

  return timingSafeEqualHashes(currentHash, claimedRoot);
}
