import { NodeQuarantineRecord } from './types.js';
import { NodeRegistry } from './identity.js';

export class NodeQuarantineManager {
  private nodeRegistry: NodeRegistry;
  private quarantineRecords = new Map<string, NodeQuarantineRecord>();

  constructor(nodeRegistry: NodeRegistry) {
    this.nodeRegistry = nodeRegistry;
  }

  /**
   * Quarantines a node due to detected divergence or signature violation while preserving forensic evidence.
   */
  public quarantineNode(
    nodeId: string,
    reason: NodeQuarantineRecord['reason'],
    lastValidEventSequence: bigint,
    lastValidEventHash: Buffer,
    triggeringEvidence: Record<string, unknown>,
    quarantineAuthority: string,
    lastValidCheckpointId?: string
  ): NodeQuarantineRecord {
    // 1. Set node status to QUARANTINED in registry
    this.nodeRegistry.setNodeStatus(nodeId, 'QUARANTINED');

    // 2. Snapshot quarantine record
    const record: NodeQuarantineRecord = {
      nodeId,
      quarantineEpochUs: BigInt(Date.now()) * 1000n,
      reason,
      lastValidEventSequence,
      lastValidEventHash,
      lastValidCheckpointId,
      triggeringEvidence,
      quarantineAuthority,
    };

    this.quarantineRecords.set(nodeId, record);
    return record;
  }

  public getQuarantineRecord(nodeId: string): NodeQuarantineRecord | null {
    return this.quarantineRecords.get(nodeId) || null;
  }

  public getAllQuarantinedNodes(): NodeQuarantineRecord[] {
    return Array.from(this.quarantineRecords.values());
  }
}
