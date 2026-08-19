import { INetworkTransport, DirectMemoryNetworkTransport } from './network_transport.js';
import { GrpcNetworkTransport, GrpcAttestServer, GrpcReplicateServer } from './grpc_transport.js';
import { TrustValidatorDaemon } from './validator_daemon.js';
import { TrustLedgerReplicaNode } from './ledger_replica.js';
import { TrustGatewayServer } from './gateway.js';
import { TrustGatewayConfig } from './types.js';

export interface ClusterOptions {
  requiredQuorum?: number;
  totalValidators?: number;
  totalReplicas?: number;
  validatorSetId?: string;
  useGrpc?: boolean;
  basePort?: number;
}

export class DistributedTrustCluster {
  public readonly transport: INetworkTransport;
  public readonly gateway: TrustGatewayServer;
  public readonly validators: Map<string, TrustValidatorDaemon> = new Map();
  public readonly replicas: Map<string, TrustLedgerReplicaNode> = new Map();
  private readonly options: ClusterOptions;
  private isStarted = false;

  constructor(options: ClusterOptions = {}) {
    this.options = options;
    const requiredQuorum = options.requiredQuorum ?? 3;
    const totalValidators = options.totalValidators ?? 5;
    const totalReplicas = options.totalReplicas ?? 3;
    const validatorSetId = options.validatorSetId ?? 'valset-genesis';
    const basePort = options.basePort ?? 9000;

    this.transport = options.useGrpc ? new GrpcNetworkTransport() : new DirectMemoryNetworkTransport();

    const validatorEndpoints: Array<{ validatorId: string; endpoint: string }> = [];
    for (let i = 1; i <= totalValidators; i++) {
      const vId = `val-node-${i.toString().padStart(2, '0')}`;
      const port = basePort + i;
      const endpoint = `http://127.0.0.1:${port}`;
      validatorEndpoints.push({ validatorId: vId, endpoint });

      const daemon = new TrustValidatorDaemon({
        validatorId: vId,
        validatorSetId,
        port,
        host: '127.0.0.1',
        publicKeyHex: '',
      });
      if (!options.useGrpc) {
        daemon.start(this.transport);
      }
      this.validators.set(vId, daemon);
    }

    const replicaEndpoints: Array<{ replicaId: string; endpoint: string }> = [];
    for (let i = 1; i <= totalReplicas; i++) {
      const rId = `replica-node-${i.toString().padStart(2, '0')}`;
      const port = basePort + 100 + i;
      const endpoint = `http://127.0.0.1:${port}`;
      replicaEndpoints.push({ replicaId: rId, endpoint });

      const replica = new TrustLedgerReplicaNode({
        replicaId: rId,
        port,
        host: '127.0.0.1',
        role: i === 1 ? 'PRIMARY' : i === 2 ? 'BACKUP' : 'AUDIT',
      });
      if (!options.useGrpc) {
        replica.start(this.transport);
      }
      this.replicas.set(rId, replica);
    }

    const gatewayConfig: TrustGatewayConfig = {
      gatewayId: 'gateway-prod-01',
      port: basePort - 1000 > 0 ? basePort - 1000 : 8080,
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

  public async start(): Promise<void> {
    if (this.isStarted) return;
    if (this.options.useGrpc) {
      for (const daemon of this.validators.values()) {
        await daemon.startGrpc(daemon.config.port, daemon.config.host);
      }
      for (const replica of this.replicas.values()) {
        await replica.startGrpc(replica.config.port, replica.config.host);
      }
    }
    this.isStarted = true;
  }

  public async stop(): Promise<void> {
    if (this.options.useGrpc) {
      for (const daemon of this.validators.values()) {
        await daemon.stop();
      }
      for (const replica of this.replicas.values()) {
        await replica.stop();
      }
      if ('closeAll' in this.transport) {
        (this.transport as any).closeAll();
      }
    }
    this.isStarted = false;
  }

  public static async create(options: ClusterOptions = {}): Promise<DistributedTrustCluster> {
    const cluster = new DistributedTrustCluster(options);
    await cluster.start();
    return cluster;
  }

  public simulateValidatorPartition(validatorId: string, isPartitioned: boolean): void {
    const daemon = this.validators.get(validatorId);
    if (daemon && 'setEndpointOffline' in this.transport) {
      (this.transport as any).setEndpointOffline(`http://${daemon.config.host}:${daemon.config.port}`, isPartitioned);
    }
  }

  public simulateGatewayOutage(isOutage: boolean): void {
    this.gateway.setOnlineStatus(!isOutage);
  }
}
