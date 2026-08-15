import crypto from 'node:crypto';
import {
  NodeCheckpointAttestation,
  FederatedConsensusPolicy,
  FederatedConsensusVerdict,
} from './types.js';
import { NodeRegistry } from './identity.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export function computeCheckpointAttestationDigest(
  checkpointId: string,
  checkpointDigest: Buffer,
  commitSeq: bigint,
  merkleRoot: Buffer,
  timestampUs: bigint
): Buffer {
  const domain = Buffer.from('WDB:FED_CHK_ATTEST:v1:', 'utf8');

  const chkIdBuf = Buffer.alloc(16);
  Buffer.from(checkpointId.replace(/-/g, ''), 'hex').copy(chkIdBuf, 0);

  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigInt64BE(commitSeq, 0);

  const timeBuf = Buffer.alloc(8);
  timeBuf.writeBigInt64BE(timestampUs, 0);

  const preimage = Buffer.concat([domain, chkIdBuf, checkpointDigest, seqBuf, merkleRoot, timeBuf]);
  return crypto.createHash('sha256').update(preimage).digest();
}

export class FederatedConsensusEngine {
  private nodeRegistry: NodeRegistry;

  constructor(nodeRegistry: NodeRegistry) {
    this.nodeRegistry = nodeRegistry;
  }

  /**
   * Generates a signed checkpoint attestation for a node.
   */
  public createAttestation(
    nodeId: string,
    checkpointId: string,
    checkpointDigest: Buffer,
    commitSeq: bigint,
    merkleRoot: Buffer,
    privateKey: crypto.KeyObject
  ): NodeCheckpointAttestation {
    const timestampUs = BigInt(Date.now()) * 1000n;
    const digest = computeCheckpointAttestationDigest(
      checkpointId,
      checkpointDigest,
      commitSeq,
      merkleRoot,
      timestampUs
    );
    const signature = crypto.sign(null, digest, privateKey);

    return {
      nodeId,
      checkpointId,
      checkpointDigest,
      commitSeq,
      merkleRoot,
      timestampUs,
      signature,
    };
  }

  /**
   * Evaluates federated consensus across multi-node attestations against expected checkpoint digest.
   */
  public evaluateConsensus(
    expectedCheckpointDigest: Buffer,
    attestations: NodeCheckpointAttestation[],
    policy: FederatedConsensusPolicy
  ): {
    verdict: FederatedConsensusVerdict;
    validMatchingNodes: string[];
    divergentNodes: string[];
    untrustedNodes: string[];
    summary: string;
  } {
    const validMatchingNodes: string[] = [];
    const divergentNodes: string[] = [];
    const untrustedNodes: string[] = [];

    for (const att of attestations) {
      const node = this.nodeRegistry.getNode(att.nodeId);
      if (!node || node.status !== 'TRUSTED') {
        untrustedNodes.push(att.nodeId);
        continue;
      }

      // Verify signature
      const digest = computeCheckpointAttestationDigest(
        att.checkpointId,
        att.checkpointDigest,
        att.commitSeq,
        att.merkleRoot,
        att.timestampUs
      );

      let isSigValid = false;
      try {
        const pubKeyObject = crypto.createPublicKey({
          key: Buffer.concat([
            Buffer.from('302a300506032b6570032100', 'hex'),
            node.publicKey,
          ]),
          format: 'der',
          type: 'spki',
        });
        isSigValid = crypto.verify(null, digest, pubKeyObject, att.signature);
      } catch {
        isSigValid = false;
      }

      if (!isSigValid) {
        untrustedNodes.push(att.nodeId);
        continue;
      }

      if (timingSafeEqualHashes(att.checkpointDigest, expectedCheckpointDigest)) {
        validMatchingNodes.push(att.nodeId);
      } else {
        divergentNodes.push(att.nodeId);
      }
    }

    let verdict: FederatedConsensusVerdict;
    let summary: string;

    if (validMatchingNodes.length >= policy.requiredQuorum) {
      verdict = 'FEDERATION_CONSENSUS_VALID';
      summary = `Federated Quorum Satisfied: ${validMatchingNodes.length}/${policy.totalNodes} nodes agree (required: ${policy.requiredQuorum})`;
    } else if (validMatchingNodes.length > 0 && validMatchingNodes.length < policy.requiredQuorum) {
      verdict = 'FEDERATION_CONSENSUS_DEGRADED';
      summary = `Degraded Quorum: ${validMatchingNodes.length}/${policy.totalNodes} nodes agree (required: ${policy.requiredQuorum})`;
    } else if (divergentNodes.length > 0) {
      verdict = 'FEDERATION_CONSENSUS_DIVERGENCE';
      summary = `Federation Divergence: ${divergentNodes.length} nodes report conflicting state roots`;
    } else {
      verdict = 'FEDERATION_CONSENSUS_INDETERMINATE';
      summary = 'Insufficient active attestations to determine consensus';
    }

    return {
      verdict,
      validMatchingNodes,
      divergentNodes,
      untrustedNodes,
      summary,
    };
  }
}
