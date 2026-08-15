import { AttestRpcRequest, AttestRpcResponse, ReplicateRecordRpcRequest, ReplicateRecordRpcResponse } from './types.js';

export interface INetworkTransport {
  sendAttestRpc(endpoint: string, request: AttestRpcRequest): Promise<AttestRpcResponse>;
  sendReplicateRpc(endpoint: string, request: ReplicateRecordRpcRequest): Promise<ReplicateRecordRpcResponse>;
}

export class DirectMemoryNetworkTransport implements INetworkTransport {
  private attestHandlers = new Map<string, (req: AttestRpcRequest) => Promise<AttestRpcResponse>>();
  private replicateHandlers = new Map<string, (req: ReplicateRecordRpcRequest) => Promise<ReplicateRecordRpcResponse>>();
  private offlineEndpoints = new Set<string>();

  public registerAttestEndpoint(endpoint: string, handler: (req: AttestRpcRequest) => Promise<AttestRpcResponse>): void {
    this.attestHandlers.set(endpoint, handler);
  }

  public registerReplicateEndpoint(endpoint: string, handler: (req: ReplicateRecordRpcRequest) => Promise<ReplicateRecordRpcResponse>): void {
    this.replicateHandlers.set(endpoint, handler);
  }

  public setEndpointOffline(endpoint: string, isOffline: boolean): void {
    if (isOffline) {
      this.offlineEndpoints.add(endpoint);
    } else {
      this.offlineEndpoints.delete(endpoint);
    }
  }

  public async sendAttestRpc(endpoint: string, request: AttestRpcRequest): Promise<AttestRpcResponse> {
    if (this.offlineEndpoints.has(endpoint)) {
      throw new Error(`Endpoint ${endpoint} is offline / unreachable (Network Timeout)`);
    }
    const handler = this.attestHandlers.get(endpoint);
    if (!handler) {
      throw new Error(`No attest handler registered for endpoint ${endpoint}`);
    }
    return handler(request);
  }

  public async sendReplicateRpc(endpoint: string, request: ReplicateRecordRpcRequest): Promise<ReplicateRecordRpcResponse> {
    if (this.offlineEndpoints.has(endpoint)) {
      throw new Error(`Endpoint ${endpoint} is offline / unreachable (Network Timeout)`);
    }
    const handler = this.replicateHandlers.get(endpoint);
    if (!handler) {
      throw new Error(`No replicate handler registered for endpoint ${endpoint}`);
    }
    return handler(request);
  }
}
