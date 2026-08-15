import crypto from 'node:crypto';
import { ByzantineTrustValidator } from '../trust_service/byzantine_validator.js';
import { DirectMemoryNetworkTransport } from '../runtime/network_transport.js';
import { AttestRpcRequest, AttestRpcResponse } from '../runtime/types.js';

export interface StandaloneValidatorOptions {
  id: string;
  listenHost: string;
  listenPort: number;
  dataDir: string;
  epoch: number;
}

export class StandaloneValidatorProcess {
  public readonly options: StandaloneValidatorOptions;
  public readonly validator: ByzantineTrustValidator;
  public readonly endpoint: string;

  constructor(
    options: StandaloneValidatorOptions,
    keyPair?: { publicKey: Buffer; privateKey: crypto.KeyObject }
  ) {
    this.options = options;
    this.endpoint = `http://${options.listenHost}:${options.listenPort}`;
    this.validator = new ByzantineTrustValidator(
      {
        validatorId: options.id,
        validatorSetId: `valset-epoch-${options.epoch}`,
        epoch: options.epoch,
        port: options.listenPort,
        host: options.listenHost,
      },
      keyPair
    );
  }

  public bind(transport: DirectMemoryNetworkTransport): void {
    transport.registerAttestEndpoint(this.endpoint, async (req: AttestRpcRequest): Promise<AttestRpcResponse> => {
      try {
        const customerPubkey = Buffer.from(req.tenantPubkeyHex, 'hex');
        const attestation = this.validator.attestCommitment(req.commitment, customerPubkey);
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
    });
  }
}
