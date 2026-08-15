import crypto from 'node:crypto';
import {
  CorrelationGraphNode,
  CorrelationGraphEdge,
  CorrelationNodeType,
  CorrelationEdgeRelationship,
  SecurityEventEnvelope,
} from './types.js';
import { canonicalizeJson } from '../binary/c14n.js';

export class IncidentCorrelationGraph {
  public readonly incidentId: string;
  private nodes = new Map<string, CorrelationGraphNode>();
  private edges: CorrelationGraphEdge[] = [];

  constructor(incidentId: string) {
    this.incidentId = incidentId;
  }

  public addNode(
    nodeId: string,
    nodeType: CorrelationNodeType,
    label: string,
    attributes: Record<string, unknown> = {},
    evidenceEventId?: string
  ): CorrelationGraphNode {
    const node: CorrelationGraphNode = {
      nodeId,
      nodeType,
      label,
      attributes,
      evidenceEventId,
    };
    this.nodes.set(nodeId, node);
    return node;
  }

  public addEdge(
    sourceNodeId: string,
    targetNodeId: string,
    relationship: CorrelationEdgeRelationship,
    weight = 1.0,
    evidenceContext: Record<string, unknown> = {}
  ): CorrelationGraphEdge {
    if (!this.nodes.has(sourceNodeId)) {
      throw new Error(`CorrelationGraph: Source node "${sourceNodeId}" does not exist`);
    }
    if (!this.nodes.has(targetNodeId)) {
      throw new Error(`CorrelationGraph: Target node "${targetNodeId}" does not exist`);
    }

    const canonicalContext = canonicalizeJson(evidenceContext);
    const evidenceDigest = crypto
      .createHash('sha256')
      .update(Buffer.from(canonicalContext, 'utf8'))
      .digest();

    const edge: CorrelationGraphEdge = {
      sourceNodeId,
      targetNodeId,
      relationship,
      weight,
      evidenceDigest,
    };
    this.edges.push(edge);
    return edge;
  }

  public ingestSecurityEvent(event: SecurityEventEnvelope): void {
    const eventNodeId = `evt:${event.eventId}`;
    this.addNode(
      eventNodeId,
      'RUNTIME_CONTEXT',
      `${event.plane}:${event.eventType}`,
      event.payload,
      event.eventId
    );

    const actorNodeId = `actor:${event.actorId}`;
    if (!this.nodes.has(actorNodeId)) {
      this.addNode(actorNodeId, 'ACTOR', `Actor: ${event.actorId}`, { actorId: event.actorId });
    }

    this.addEdge(actorNodeId, eventNodeId, 'INITIATED_BY', 1.0, {
      plane: event.plane,
      timestampUs: event.timestampUs.toString(),
    });
  }

  public getNodeCount(): number {
    return this.nodes.size;
  }

  public getEdgeCount(): number {
    return this.edges.length;
  }

  public getNodes(): CorrelationGraphNode[] {
    return Array.from(this.nodes.values());
  }

  public getEdges(): CorrelationGraphEdge[] {
    return [...this.edges];
  }

  public computeGraphRootDigest(): Buffer {
    const serializedNodes = Array.from(this.nodes.values()).map((n) => ({
      id: n.nodeId,
      type: n.nodeType,
      label: n.label,
    }));
    const serializedEdges = this.edges.map((e) => ({
      src: e.sourceNodeId,
      tgt: e.targetNodeId,
      rel: e.relationship,
      weight: e.weight,
    }));

    const canonicalGraph = canonicalizeJson({
      incidentId: this.incidentId,
      nodes: serializedNodes,
      edges: serializedEdges,
    });

    return crypto.createHash('sha256').update(Buffer.from(canonicalGraph, 'utf8')).digest();
  }
}
