import crypto from 'node:crypto';
import { NodeIdentity, NodeTrustStatus, NodeCapability } from './types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export function computeNodeAttestationDigest(
  nodeId: string,
  publicKey: Buffer,
  creationEpochUs: bigint,
  organizationId: string,
  clusterId: string
): Buffer {
  const domain = Buffer.from('WDB:NODE_ID:v1:', 'utf8');

  const nodeIdBuf = Buffer.from(nodeId, 'utf8');
  const nodeIdLenBuf = Buffer.alloc(2);
  nodeIdLenBuf.writeUInt16BE(nodeIdBuf.length, 0);

  const timeBuf = Buffer.alloc(8);
  timeBuf.writeBigInt64BE(creationEpochUs, 0);

  const orgBuf = Buffer.from(organizationId, 'utf8');
  const clusterBuf = Buffer.from(clusterId, 'utf8');

  const preimage = Buffer.concat([
    domain,
    nodeIdLenBuf,
    nodeIdBuf,
    publicKey,
    timeBuf,
    orgBuf,
    clusterBuf,
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
    const creationEpochUs = BigInt(Date.now()) * 1000n;
    const digest = computeNodeAttestationDigest(
      nodeId,
      publicKey,
      creationEpochUs,
      organizationId,
      clusterId
    );

    let attestationSignature: Buffer;
    if (privateKey) {
      attestationSignature = crypto.sign(null, digest, privateKey);
    } else {
      attestationSignature = Buffer.alloc(64, 0);
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

  public getNode(nodeId: string): NodeIdentity | null {
    return this.nodes.get(nodeId) || null;
  }

  public setNodeStatus(nodeId: string, status: NodeTrustStatus): void {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new WolverineError(WolverineErrorCode.INVALID_CONFIGURATION, `Node "${nodeId}" not found in registry`);
    }
    node.status = status;
  }

  public isNodeTrusted(nodeId: string): boolean {
    const node = this.nodes.get(nodeId);
    return !!node && node.status === 'TRUSTED';
  }

  public getAllNodes(): NodeIdentity[] {
    return Array.from(this.nodes.values());
  }
}
