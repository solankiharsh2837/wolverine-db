import crypto from 'node:crypto';
import { NodeIdentity, NodeTrustStatus, NodeCapability } from './types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { encodeProtocolTuple } from '../crypto/canonical.js';

export function computeNodeAttestationDigest(
  nodeId: string,
  publicKey: Buffer,
  creationEpochUs: bigint,
  organizationId: string,
  clusterId: string
): Buffer {
  const preimage = encodeProtocolTuple('WDB:NODE_ID:v2:', [
    nodeId,
    publicKey,
    BigInt(creationEpochUs),
    organizationId,
    clusterId,
  ]);

  return crypto.createHash('sha256').update(preimage).digest();
}

export class NodeRegistry {
  private nodes = new Map<string, NodeIdentity>();

  /**
   * Registers a node in the federation registry with strict cryptographic attestation.
   * If a privateKey is provided, signs the attestation and sets status to 'TRUSTED'.
   * If no valid signature is provided, node status is 'UNATTESTED' (never falsely trusted).
   */
  public registerNode(
    nodeId: string,
    publicKey: Buffer,
    capabilities: NodeCapability[],
    organizationId: string,
    clusterId: string,
    privateKey?: crypto.KeyObject,
    providedSignature?: Buffer
  ): NodeIdentity {
    if (this.nodes.has(nodeId)) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Node ${nodeId} already registered in local federation registry`
      );
    }

    const creationEpochUs = BigInt(Date.now()) * 1000n;
    const attestationDigest = computeNodeAttestationDigest(
      nodeId,
      publicKey,
      creationEpochUs,
      organizationId,
      clusterId
    );

    let attestationSignature: Buffer;
    let status: NodeTrustStatus;

    if (privateKey) {
      // Derive public key to ensure correspondence
      const derivedPub = crypto
        .createPublicKey(privateKey)
        .export({ type: 'spki', format: 'der' })
        .subarray(-32);

      if (Buffer.compare(derivedPub, publicKey) !== 0) {
        throw new WolverineError(
          WolverineErrorCode.UNAUTHORIZED_MUTATION,
          `Keypair correspondence failure: privateKey does not derive public key for node ${nodeId}`
        );
      }

      attestationSignature = crypto.sign(null, attestationDigest, privateKey);
      status = 'TRUSTED';
    } else if (providedSignature) {
      attestationSignature = providedSignature;
      status = 'ATTESTATION_PENDING';
    } else {
      attestationSignature = Buffer.alloc(64, 0);
      status = 'UNATTESTED';
    }

    const identity: NodeIdentity = {
      nodeId,
      publicKey,
      capabilities,
      creationEpochUs,
      organizationId,
      clusterId,
      status,
      attestationSignature,
    };

    // If attestation was pending with provided signature, verify it
    if (status === 'ATTESTATION_PENDING') {
      if (this.verifyNodeIdentity(identity)) {
        identity.status = 'TRUSTED';
      } else {
        identity.status = 'UNATTESTED';
      }
    }

    this.nodes.set(nodeId, identity);
    return identity;
  }

  public getNode(nodeId: string): NodeIdentity | undefined {
    return this.nodes.get(nodeId);
  }

  public setNodeStatus(nodeId: string, status: NodeTrustStatus): void {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new WolverineError(
        WolverineErrorCode.UNTRUSTED_APPROVER_KEY,
        `Node ${nodeId} not found in registry`
      );
    }
    node.status = status;
  }

  /**
   * Cryptographically verifies whether a node is currently trusted.
   * Requires status == 'TRUSTED' and a mathematically valid Ed25519 attestation signature.
   */
  public isNodeTrusted(nodeId: string): boolean {
    const node = this.nodes.get(nodeId);
    if (!node) return false;
    if (node.status !== 'TRUSTED') return false;
    return this.verifyNodeIdentity(node);
  }

  public verifyNodeIdentity(identity: NodeIdentity): boolean {
    const expectedDigest = computeNodeAttestationDigest(
      identity.nodeId,
      identity.publicKey,
      identity.creationEpochUs,
      identity.organizationId,
      identity.clusterId
    );

    const ed25519SpkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
    const spkiBuffer = Buffer.concat([ed25519SpkiHeader, identity.publicKey]);

    try {
      const publicKeyObject = crypto.createPublicKey({
        key: spkiBuffer,
        format: 'der',
        type: 'spki',
      });

      return crypto.verify(
        null,
        expectedDigest,
        publicKeyObject,
        identity.attestationSignature
      );
    } catch {
      return false;
    }
  }
}
