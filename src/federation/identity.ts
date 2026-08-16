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

  public registerNode(
    nodeId: string,
    publicKey: Buffer,
    capabilities: NodeCapability[],
    organizationId: string,
    clusterId: string,
    privateKey?: crypto.KeyObject
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

    let attestationSignature = Buffer.alloc(64, 0);
    if (privateKey) {
      attestationSignature = crypto.sign(null, attestationDigest, privateKey);
    }

    const identity: NodeIdentity = {
      nodeId,
      publicKey,
      capabilities,
      creationEpochUs,
      organizationId,
      clusterId,
      status: 'TRUSTED',
      attestationSignature,
    };

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

  public isNodeTrusted(nodeId: string): boolean {
    const node = this.nodes.get(nodeId);
    return !!node && node.status === 'TRUSTED';
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
