import crypto from 'node:crypto';
import { ProofGraphNode, ReconstructionProofGraph } from './types.js';
import { canonicalizeJson } from '../binary/c14n.js';

export function computeReconstructionGraphDigest(graph: ReconstructionProofGraph): Buffer {
  const domain = Buffer.from('WDB:PROOF_GRAPH:v1:', 'utf8');

  const serializableNodes = graph.nodes.map((n) => ({
    nodeId: n.nodeId,
    type: n.type,
    commitSeq: n.commitSeq.toString(),
    hashHex: n.hash.toString('hex'),
    parentIds: n.parentIds,
    evaluationStatus: n.evaluationStatus,
  }));

  const canonicalPayload = canonicalizeJson({
    nodes: serializableNodes,
    edges: graph.edges,
  });

  return crypto
    .createHash('sha256')
    .update(Buffer.concat([domain, Buffer.from(canonicalPayload, 'utf8')]))
    .digest();
}

export class ReconstructionProofGraphBuilder {
  private nodes: ProofGraphNode[] = [];
  private edges: Array<{ from: string; to: string; relationship: string }> = [];

  public addCheckpointNode(
    checkpointId: string,
    commitSeq: bigint,
    digest: Buffer
  ): string {
    const nodeId = `chk:${checkpointId}`;
    this.nodes.push({
      nodeId,
      type: 'CHECKPOINT',
      commitSeq,
      hash: digest,
      parentIds: [],
      proofData: { checkpointId },
      evaluationStatus: 'VERIFIED',
    });
    return nodeId;
  }

  public addMutationProofPath(
    changeId: string,
    commitSeq: bigint,
    computedHash: Buffer,
    predecessorNodeId: string,
    isAuthValid: boolean,
    isProvValid: boolean,
    isIndependentAnchor: boolean = false
  ): {
    mutationNodeId: string;
    authNodeId: string;
    provNodeId: string;
  } {
    const mutationNodeId = `mut:${changeId}`;
    const authNodeId = `auth:${changeId}`;
    const provNodeId = `prov:${changeId}`;

    // 1. Auth Node
    this.nodes.push({
      nodeId: authNodeId,
      type: 'AUTHORIZATION',
      commitSeq,
      hash: crypto.createHash('sha256').update(Buffer.from(`auth:${changeId}:${isAuthValid}`)).digest(),
      parentIds: [],
      proofData: { isAuthValid },
      evaluationStatus: isAuthValid ? 'VERIFIED' : 'FAILED',
    });

    // 2. Prov Node
    this.nodes.push({
      nodeId: provNodeId,
      type: 'PROVENANCE',
      commitSeq,
      hash: crypto.createHash('sha256').update(Buffer.from(`prov:${changeId}:${isProvValid}`)).digest(),
      parentIds: [],
      proofData: { isProvValid },
      evaluationStatus: isProvValid ? 'VERIFIED' : 'FAILED',
    });

    // 3. Mutation Node
    const evalStatus = isAuthValid && isProvValid ? 'VERIFIED' : 'FAILED';
    this.nodes.push({
      nodeId: mutationNodeId,
      type: 'MUTATION',
      commitSeq,
      hash: computedHash,
      parentIds: [predecessorNodeId, authNodeId, provNodeId],
      proofData: { changeId, isIndependentAnchor },
      evaluationStatus: evalStatus,
    });

    // Edges
    this.edges.push({ from: predecessorNodeId, to: mutationNodeId, relationship: 'PREDECESSOR' });
    this.edges.push({ from: authNodeId, to: mutationNodeId, relationship: 'AUTHORIZED_BY' });
    this.edges.push({ from: provNodeId, to: mutationNodeId, relationship: 'PROVENANCE_TRACE' });

    return { mutationNodeId, authNodeId, provNodeId };
  }

  public build(): ReconstructionProofGraph {
    return {
      nodes: this.nodes,
      edges: this.edges,
    };
  }
}
