import { LedgerReplicaConfig, ReplicateRecordRpcRequest, ReplicateRecordRpcResponse } from './types.js';
import { WolverineTrustLedger } from '../trust_network/ledger.js';
import { INetworkTransport, DirectMemoryNetworkTransport } from './network_transport.js';

export class TrustLedgerReplicaNode {
  public readonly config: LedgerReplicaConfig;
  private ledger: WolverineTrustLedger;
  private endpoint: string;

  private grpcServer?: any;

  constructor(config: LedgerReplicaConfig) {
    this.config = config;
    this.ledger = new WolverineTrustLedger();
    this.endpoint = `http://${config.host}:${config.port}`;
  }

  public getLedger(): WolverineTrustLedger {
    return this.ledger;
  }

  public start(transport: INetworkTransport): void {
    if ('registerReplicateEndpoint' in transport) {
      (transport as any).registerReplicateEndpoint(this.endpoint, async (req: ReplicateRecordRpcRequest): Promise<ReplicateRecordRpcResponse> => {
        return this.handleReplicateRequest(req);
      });
    }
  }

  public async startGrpc(port: number, host: string, tlsConfig?: any): Promise<any> {
    const { GrpcReplicateServer } = await import('./grpc_transport.js');
    this.grpcServer = new GrpcReplicateServer(async (req) => this.handleReplicateRequest(req), tlsConfig);
    await this.grpcServer.listen(port, host);
    return this.grpcServer;
  }

  public async stop(): Promise<void> {
    if (this.grpcServer) {
      await this.grpcServer.close();
      this.grpcServer = undefined;
    }
  }

  public async handleReplicateRequest(req: ReplicateRecordRpcRequest): Promise<ReplicateRecordRpcResponse> {
    try {
      const record = req.record;
      // Append record into replica's local ledger
      const appended = this.ledger.appendRecord(
        record.recordType,
        record.payload,
        record.epoch,
        record.validatorSetId,
        record.tenantId,
        record.databaseId
      );

      return {
        success: true,
        acknowledgedSeq: appended.ledgerSeq.toString(),
      };
    } catch (err: any) {
      return {
        success: false,
        acknowledgedSeq: '0',
        error: err.message,
      };
    }
  }
}
