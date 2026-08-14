import { describe, it, expect } from 'vitest';
import {
  MerkleTree,
  verifyMerkleProof,
  EMPTY_TREE_ROOT,
  computeMerkleLeafHash,
} from '../src/crypto/merkle.js';

describe('Merkle Tree Engine (WDB-0004)', () => {
  it('returns empty root constant for zero leaves', () => {
    const tree = new MerkleTree([]);
    expect(tree.root.toString('hex')).toBe(EMPTY_TREE_ROOT.toString('hex'));
  });

  it('builds tree and verifies inclusion proof for single leaf', () => {
    const payload = Buffer.from('leaf1', 'utf8');
    const tree = new MerkleTree([payload]);

    const leafHash = computeMerkleLeafHash(payload);
    expect(tree.root.toString('hex')).toBe(leafHash.toString('hex'));

    const proof = tree.generateProof(0);
    expect(verifyMerkleProof(proof.leafHash, proof.proof, tree.root)).toBe(true);
  });

  it('builds tree with odd leaf count (duplicates final hash) and verifies inclusion proof', () => {
    const p1 = Buffer.from('leaf1', 'utf8');
    const p2 = Buffer.from('leaf2', 'utf8');
    const p3 = Buffer.from('leaf3', 'utf8');

    const tree = new MerkleTree([p1, p2, p3]);

    for (let i = 0; i < 3; i++) {
      const proof = tree.generateProof(i);
      expect(verifyMerkleProof(proof.leafHash, proof.proof, tree.root)).toBe(true);
    }
  });

  it('rejects inclusion proof if sibling hash is tampered', () => {
    const p1 = Buffer.from('leaf1', 'utf8');
    const p2 = Buffer.from('leaf2', 'utf8');
    const tree = new MerkleTree([p1, p2]);

    const proof = tree.generateProof(0);
    proof.proof[0].siblingHash = Buffer.alloc(32, 0xff); // Tamper sibling hash

    expect(verifyMerkleProof(proof.leafHash, proof.proof, tree.root)).toBe(false);
  });
});
