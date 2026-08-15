import { DistributedTrustCluster } from './cluster.js';
import { TrustTimeRecord } from './types.js';

export class WolverineRuntimeCli {
  /**
   * wdb cluster status
   */
  public static executeClusterStatus(cluster: DistributedTrustCluster): string {
    const lines = [
      '================================================================================',
      '                     WOLVERINE DISTRIBUTED TRUST CLUSTER                        ',
      '================================================================================',
      `Gateway ID:               ${cluster.gateway.config.gatewayId} (Port ${cluster.gateway.config.port})`,
      `Validator Quorum Policy:  ${cluster.gateway.config.requiredQuorum} / ${cluster.gateway.config.totalValidators}`,
      `Active Validators:        ${cluster.validators.size} Daemons`,
      `Active Ledger Replicas:   ${cluster.replicas.size} Nodes`,
      '',
      'Validator Topology:',
    ];

    for (const [vId, daemon] of cluster.validators.entries()) {
      lines.push(`  ✓ ${vId.padEnd(16)} (Port ${daemon.config.port}) PubKey: ${daemon.getPublicKey().toString('hex').slice(0, 16)}...`);
    }

    lines.push('');
    lines.push('Ledger Replica Topology:');
    for (const [rId, replica] of cluster.replicas.entries()) {
      lines.push(`  ✓ ${rId.padEnd(16)} (Port ${replica.config.port}) Role: ${replica.config.role} [SYNCED]`);
    }

    lines.push('================================================================================');
    return lines.join('\n');
  }

  /**
   * wdb trust-time inspect
   */
  public static executeTrustTimeInspect(record: TrustTimeRecord): string {
    const lines = [
      '================================================================================',
      '                       WOLVERINE DUAL-TIMELINE RECORD                           ',
      '================================================================================',
      `Database ID:              ${record.databaseId}`,
      `Database Time:            CommitSeq ${record.commitSeq}`,
      `Checkpoint ID:            ${record.checkpointId}`,
      `Checkpoint Digest:        ${record.checkpointDigestHex.slice(0, 32)}...`,
      `Trust Time Sequence:      LedgerSeq ${record.ledgerSeq}`,
      `Network Epoch:            ${record.epoch}`,
      `Finalized Timestamp Us:   ${record.finalizedAtUs}`,
      `Consensus Quorum Digest:  ${record.quorumDigestHex.slice(0, 32)}...`,
      '================================================================================',
    ];
    return lines.join('\n');
  }
}
