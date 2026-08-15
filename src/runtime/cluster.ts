import { DirectMemoryNetworkTransport } from './network_transport.js';
import { TrustValidatorDaemon } from './validator_daemon.js';
import { TrustLedgerReplicaNode } from './ledger_replica.js';
import { TrustGatewayServer } from './gateway.js';
import { TrustGatewayConfig } from './types.js';

export interface ClusterOptions {
  requiredQuorum?: number;
  totalValidators?: number;
  totalReplicas?: number;
  validatorSetId?: string;
}

export class DistributedTrustCluster {
  public readonly transport: DirectMemoryNetworkTransport;
  public readonly gateway: TrustGatewayServer;
  public readonly validators: Map<string, TrustValidatorDaemon> = new Map();
  public readonly replicas: Map<string, TrustLedgerReplicaNode> = new Map();

  constructor(options: ClusterOptions = {}) {
    const requiredQuorum = options.requiredQuorum ?? 3;
    const totalValidators = options.totalValidators ?? 5;
    const totalReplicas = options.totalReplicas ?? 3;
    const validatorSetId = options.validatorSetId ?? 'valset-genesis';

    this.transport = new DirectMemoryNetworkTransport();

    const validatorEndpoints: Array<{ validatorId: string; endpoint: string }> = [];
    for (let i = 1; i <= totalValidators; i++) {
      const vId = `val-node-${i.toString().padStart(2, '0')}`;
      const port = 9000 + i;
      const endpoint = `http://127.0.0.1:${port}`;
      validatorEndpoints.push({ validatorId: vId, endpoint });

      const daemon = new TrustValidatorDaemon({
        validatorId: vId,
        validatorSetId,
        port,
        host: '127.0.0.1',
        publicKeyHex: '',
      });
      daemon.start(this.transport);
      this.validators.set(vId, daemon);
    }

    const replicaEndpoints: Array<{ replicaId: string; endpoint: string }> = [];
    for (let i = 1; i <= totalReplicas; i++) {
      const rId = `replica-node-${i.toString().padStart(2, '0')}`;
      const port = 9100 + i;
      const endpoint = `http://127.0.0.1:${port}`;
      replicaEndpoints.push({ replicaId: rId, endpoint });

      const replica = new TrustLedgerReplicaNode({
        replicaId: rId,
        port,
        host: '127.0.0.1',
        role: i === 1 ? 'PRIMARY' : i === 2 ? 'BACKUP' : 'AUDIT',
      });
      replica.start(this.transport);
      this.replicas.set(rId, replica);
    }

    const gatewayConfig: TrustGatewayConfig = {
      gatewayId: 'gateway-prod-01',
      port: 8080,
      host: '127.0.0.1',
      requiredQuorum,
      totalValidators,
      validatorEndpoints,
      replicaEndpoints,
    };

    this.gateway = new TrustGatewayServer(gatewayConfig, this.transport);

    // Register validator keys in gateway
    for (const [vId, daemon] of this.validators.entries()) {
      this.gateway.registerValidatorKey(vId, daemon.getPublicKey());
    }
  }

  public simulateValidatorPartition(validatorId: string, isPartitioned: boolean): void {
    const daemon = this.validators.get(validatorId);
    if (daemon) {
      this.transport.setEndpointOffline(`http://${daemon.config.host}:${daemon.config.port}`, isPartitioned);
    }
  }

  public simulateGatewayOutage(isOutage: boolean): void {
    this.gateway.setOnlineStatus(!isOutage);
  }
}
