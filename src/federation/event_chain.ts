import crypto from 'node:crypto';
import { FederatedEventEnvelope } from './types.js';
import { SecurityEventEnvelope } from '../fabric/types.js';
import { computeEventEvidenceHash } from '../fabric/events.js';
import { NodeRegistry } from './identity.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export function computeFederatedEventChainHash(
  previousEventHash: Buffer,
  nodeSequence: bigint,
  innerEvidenceHash: Buffer
): Buffer {
  const domain = Buffer.from('WDB:FED_EVENT:v1:', 'utf8');
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigInt64BE(nodeSequence, 0);

  const preimage = Buffer.concat([domain, previousEventHash, seqBuf, innerEvidenceHash]);
  return crypto.createHash('sha256').update(preimage).digest();
}

export class FederatedEventChainBuilder {
  private nodeRegistry: NodeRegistry;
  private nodeSequenceState = new Map<string, { lastSeq: bigint; lastChainHash: Buffer }>();

  constructor(nodeRegistry: NodeRegistry) {
    this.nodeRegistry = nodeRegistry;
  }

  /**
   * Packages and signs a security event from a specific node.
   */
  public signFederatedEvent(
    originNodeId: string,
    event: SecurityEventEnvelope,
    privateKey: crypto.KeyObject
  ): FederatedEventEnvelope {
    const node = this.nodeRegistry.getNode(originNodeId);
    if (!node || node.status !== 'TRUSTED') {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Cannot emit federated event: Node "${originNodeId}" is not TRUSTED`
      );
    }

    const state = this.nodeSequenceState.get(originNodeId) || {
      lastSeq: 0n,
      lastChainHash: Buffer.alloc(32, 0),
    };

    const nextSeq = state.lastSeq + 1n;
    const previousEventHash = state.lastChainHash;

    const eventChainHash = computeFederatedEventChainHash(
      previousEventHash,
      nextSeq,
      event.evidenceHash
    );

    const nodeSignature = crypto.sign(null, eventChainHash, privateKey);

    // Advance state
    this.nodeSequenceState.set(originNodeId, {
      lastSeq: nextSeq,
      lastChainHash: eventChainHash,
    });

    return {
      event,
      originNodeId,
      nodeSequence: nextSeq,
      previousEventHash,
      eventChainHash,
      nodeSignature,
    };
  }

  /**
   * Verifies an incoming federated event envelope from a peer node.
   */
  public verifyFederatedEvent(
    envelope: FederatedEventEnvelope,
    expectedPreviousHash?: Buffer,
    expectedSeq?: bigint
  ): boolean {
    const node = this.nodeRegistry.getNode(envelope.originNodeId);
    if (!node || node.status !== 'TRUSTED') {
      return false;
    }

    // Check sequence and previous hash if expected values are supplied
    if (expectedSeq !== undefined && envelope.nodeSequence !== expectedSeq) {
      return false;
    }
    if (expectedPreviousHash && !timingSafeEqualHashes(envelope.previousEventHash, expectedPreviousHash)) {
      return false;
    }

    // Verify inner event payload evidence hash
    const expectedEvidenceHash = computeEventEvidenceHash(envelope.event.payload);
    if (!timingSafeEqualHashes(expectedEvidenceHash, envelope.event.evidenceHash)) {
      return false;
    }

    // Recompute chain hash
    const computedChainHash = computeFederatedEventChainHash(
      envelope.previousEventHash,
      envelope.nodeSequence,
      envelope.event.evidenceHash
    );

    if (!timingSafeEqualHashes(computedChainHash, envelope.eventChainHash)) {
      return false;
    }

    // Verify Ed25519 signature
    try {
      const pubKeyObject = crypto.createPublicKey({
        key: Buffer.concat([
          Buffer.from('302a300506032b6570032100', 'hex'), // Ed25519 SPKI DER prefix
          node.publicKey,
        ]),
        format: 'der',
        type: 'spki',
      });
      return crypto.verify(null, envelope.eventChainHash, pubKeyObject, envelope.nodeSignature);
    } catch {
      return false;
    }
  }
}
