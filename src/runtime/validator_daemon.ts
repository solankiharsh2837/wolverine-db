import crypto from 'node:crypto';
import { ValidatorNodeConfig, AttestRpcRequest, AttestRpcResponse } from './types.js';
import { TrustValidator } from '../trust_network/validator.js';
import { DirectMemoryNetworkTransport } from './network_transport.js';

export class TrustValidatorDaemon {
  public readonly config: ValidatorNodeConfig;
  private validator: TrustValidator;
  private endpoint: string;

  constructor(
    config: ValidatorNodeConfig,
    keyPair?: { publicKey: Buffer; privateKey: crypto.KeyObject }
  ) {
    this.config = config;
    this.validator = new TrustValidator(config.validatorId, config.validatorSetId, keyPair);
    this.endpoint = `http://${config.host}:${config.port}`;
  }

  public getPublicKey(): Buffer {
    return this.validator.publicKey;
  }

  public start(transport: DirectMemoryNetworkTransport): void {
    transport.registerAttestEndpoint(this.endpoint, async (req: AttestRpcRequest): Promise<AttestRpcResponse> => {
      return this.handleAttestRequest(req);
    });
  }

  public async handleAttestRequest(req: AttestRpcRequest): Promise<AttestRpcResponse> {
    try {
      const tenantPubkey = Buffer.from(req.tenantPubkeyHex, 'hex');
      const attestation = this.validator.attestCommitment(req.commitment, tenantPubkey);
      return {
        success: true,
        attestation,
      };
    } catch (err: any) {
      return {
        success: false,
        error: err.message,
      };
    }
  }
}
