import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { sha256, timingSafeEqualHashes } from './hash.js';

export const EMPTY_TREE_ROOT = sha256(Buffer.from('WDB:EMPTY_ROOT:v1', 'utf8'));

export interface MerkleProofStep {
  side: 0 | 1; // 0 = sibling on left, 1 = sibling on right
  siblingHash: Buffer; // 32 bytes
}

export interface MerkleProof {
  leafHash: Buffer;
  proof: MerkleProofStep[];
  root: Buffer;
}

/**
 * Computes Merkle leaf hash: SHA256("WDB:LEAF:v1" || u32be(len) || leaf_bytes)
 */
export function computeMerkleLeafHash(leafBytes: Buffer): Buffer {
  const domain = Buffer.from('WDB:LEAF:v1', 'utf8');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(leafBytes.length, 0);

  return sha256(Buffer.concat([domain, lenBuf, leafBytes]));
}

/**
 * Computes Merkle internal node hash: SHA256("WDB:NODE:v1" || left || right)
 */
export function computeMerkleNodeHash(leftHash: Buffer, rightHash: Buffer): Buffer {
  if (leftHash.length !== 32 || rightHash.length !== 32) {
    throw new WolverineError(
      WolverineErrorCode.MERKLE_ROOT_MISMATCH,
      'Merkle node left and right hashes must be 32 bytes each'
    );
  }

  const domain = Buffer.from('WDB:NODE:v1', 'utf8');
  return sha256(Buffer.concat([domain, leftHash, rightHash]));
}

export class MerkleTree {
  public readonly leaves: Buffer[];
  public readonly layers: Buffer[][];
  public readonly root: Buffer;

  constructor(leafPayloads: Buffer[]) {
    if (!leafPayloads || leafPayloads.length === 0) {
      this.leaves = [];
      this.layers = [[EMPTY_TREE_ROOT]];
      this.root = EMPTY_TREE_ROOT;
      return;
    }

    this.leaves = leafPayloads.map((payload) => computeMerkleLeafHash(payload));

    const layers: Buffer[][] = [this.leaves];
    let currentLayer = this.leaves;

    while (currentLayer.length > 1) {
      const nextLayer: Buffer[] = [];

      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        const right =
          i + 1 < currentLayer.length ? currentLayer[i + 1] : currentLayer[i]; // Duplicate if odd
        nextLayer.push(computeMerkleNodeHash(left, right));
      }

      layers.push(nextLayer);
      currentLayer = nextLayer;
    }

    this.layers = layers;
    this.root = currentLayer[0];
  }

  /**
   * Generates an inclusion proof for a given leaf index.
   */
  public generateProof(leafIndex: number): MerkleProof {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_INCLUSION_PROOF,
        `Leaf index ${leafIndex} out of bounds (0 to ${this.leaves.length - 1})`
      );
    }

    const proof: MerkleProofStep[] = [];
    let currentIndex = leafIndex;

    for (let i = 0; i < this.layers.length - 1; i++) {
      const currentLayer = this.layers[i];
      const isRightNode = currentIndex % 2 === 1;
      const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;

      const siblingHash =
        siblingIndex < currentLayer.length
          ? currentLayer[siblingIndex]
          : currentLayer[currentIndex]; // Duplicated sibling

      proof.push({
        side: isRightNode ? 0 : 1, // 0 if sibling is on left, 1 if sibling is on right
        siblingHash,
      });

      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      leafHash: this.leaves[leafIndex],
      proof,
      root: this.root,
    };
  }
}

/**
 * Verifies a Merkle inclusion proof in constant time.
 */
export function verifyMerkleProof(
  leafHash: Buffer,
  proofSteps: MerkleProofStep[],
  claimedRoot: Buffer
): boolean {
  if (leafHash.length !== 32 || claimedRoot.length !== 32) {
    return false;
  }

  let currentHash = leafHash;

  for (const step of proofSteps) {
    if (step.siblingHash.length !== 32) {
      return false;
    }

    if (step.side === 0) {
      // Sibling is on left
      currentHash = computeMerkleNodeHash(step.siblingHash, currentHash);
    } else {
      // Sibling is on right
      currentHash = computeMerkleNodeHash(currentHash, step.siblingHash);
    }
  }

  return timingSafeEqualHashes(currentHash, claimedRoot);
}
