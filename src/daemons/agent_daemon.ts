import crypto from 'node:crypto';
import { WolverineEvidenceAgentClient } from '../runtime/agent_client.js';
import { TrustGatewayServer } from '../runtime/gateway.js';

export interface StandaloneAgentOptions {
  tenantId: string;
  databaseId: string;
  gateway: TrustGatewayServer;
  keyPair?: { publicKey: Buffer; privateKey: crypto.KeyObject };
}

export class StandaloneAgentProcess {
  public readonly client: WolverineEvidenceAgentClient;
  public readonly customerPubkey: Buffer;
  public readonly customerPrivateKey: crypto.KeyObject;

  constructor(options: StandaloneAgentOptions) {
    if (options.keyPair) {
      this.customerPubkey = options.keyPair.publicKey;
      this.customerPrivateKey = options.keyPair.privateKey;
    } else {
      const generated = crypto.generateKeyPairSync('ed25519');
      this.customerPubkey = generated.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
      this.customerPrivateKey = generated.privateKey;
    }

    this.client = new WolverineEvidenceAgentClient({
      tenantId: options.tenantId,
      databaseId: options.databaseId,
      customerPubkey: this.customerPubkey,
      customerPrivateKey: this.customerPrivateKey,
      gateway: options.gateway,
    });
  }
}
