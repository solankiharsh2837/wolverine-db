import { TrustGatewayServer } from '../runtime/gateway.js';
import { DirectMemoryNetworkTransport } from '../runtime/network_transport.js';

export interface StandaloneGatewayOptions {
  id: string;
  listenHost: string;
  listenPort: number;
  validatorEndpoints: Array<{ validatorId: string; endpoint: string }>;
  replicaEndpoints: Array<{ replicaId: string; endpoint: string }>;
  requiredQuorum: number;
}

export class StandaloneGatewayProcess {
  public readonly gateway: TrustGatewayServer;

  constructor(options: StandaloneGatewayOptions, transport: DirectMemoryNetworkTransport) {
    this.gateway = new TrustGatewayServer(
      {
        gatewayId: options.id,
        host: options.listenHost,
        port: options.listenPort,
        requiredQuorum: options.requiredQuorum,
        totalValidators: options.validatorEndpoints.length,
        validatorEndpoints: options.validatorEndpoints,
        replicaEndpoints: options.replicaEndpoints,
      },
      transport
    );
  }
}
