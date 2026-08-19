import crypto from 'node:crypto';
import { ISigningProvider, SigningProviderType } from './signing_provider.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface GcpKmsClientInterface {
  asymmetricSign(params: {
    name: string;
    digest?: {
      sha256?: Uint8Array;
      sha384?: Uint8Array;
      sha512?: Uint8Array;
    };
    data?: Uint8Array;
  }): Promise<[{ signature?: Uint8Array | string }]>;
  getPublicKey(params: {
    name: string;
  }): Promise<[{ pem?: string; algorithm?: string }]>;
}

export interface GcpKmsSigningProviderOptions {
  keyVersionName: string; // e.g., projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1
  kmsClient?: GcpKmsClientInterface;
  publicKey?: Buffer;
  mockSigningKey?: crypto.KeyObject;
}

/**
 * Enterprise GCP Cloud KMS Signing Provider implementing ISigningProvider.
 * Issues cryptographic signatures over digests using Google Cloud KMS Asymmetric Keys.
 */
export class GcpKmsSigningProvider implements ISigningProvider {
  private readonly keyVersionName: string;
  private readonly kmsClient?: GcpKmsClientInterface;
  private publicKeyBytes: Buffer;
  private readonly mockSigningKey?: crypto.KeyObject;

  constructor(options: GcpKmsSigningProviderOptions) {
    if (!options.keyVersionName) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_CONFIGURATION,
        'GcpKmsSigningProvider requires a valid keyVersionName'
      );
    }
    this.keyVersionName = options.keyVersionName;
    this.kmsClient = options.kmsClient;
    this.mockSigningKey = options.mockSigningKey;

    if (options.publicKey) {
      this.publicKeyBytes = options.publicKey;
    } else if (options.mockSigningKey) {
      const pubKeyObj = crypto.createPublicKey(options.mockSigningKey);
      this.publicKeyBytes = pubKeyObj.export({ type: 'spki', format: 'der' }).subarray(-32);
    } else {
      this.publicKeyBytes = Buffer.alloc(32, 0);
    }
  }

  public getProviderType(): SigningProviderType {
    return 'GCP_KMS';
  }

  public getKeyId(): string {
    return this.keyVersionName;
  }

  public getPublicKey(): Buffer {
    return this.publicKeyBytes;
  }

  public setPublicKey(publicKey: Buffer): void {
    this.publicKeyBytes = publicKey;
  }

  public async fetchPublicKey(): Promise<Buffer> {
    if (!this.kmsClient) {
      return this.publicKeyBytes;
    }
    try {
      const [res] = await this.kmsClient.getPublicKey({ name: this.keyVersionName });
      if (res && res.pem) {
        const pubKeyObj = crypto.createPublicKey(res.pem);
        this.publicKeyBytes = pubKeyObj.export({ type: 'spki', format: 'der' }).subarray(-32);
        return this.publicKeyBytes;
      }
      throw new Error('GCP KMS getPublicKey returned empty PEM');
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.KMS_OUTAGE,
        `GCP Cloud KMS failed to fetch public key for ${this.keyVersionName}: ${err.message}`
      );
    }
  }

  public async sign(digest: Buffer): Promise<Buffer> {
    if (this.mockSigningKey) {
      return crypto.sign(null, digest, this.mockSigningKey);
    }

    if (!this.kmsClient) {
      throw new WolverineError(
        WolverineErrorCode.KMS_OUTAGE,
        `GCP Cloud KMS provider unconfigured: no live GCP KMS client or mock signing key provided for key ${this.keyVersionName}`
      );
    }

    try {
      const [res] = await this.kmsClient.asymmetricSign({
        name: this.keyVersionName,
        digest: {
          sha256: new Uint8Array(digest),
        },
      });

      if (!res || !res.signature) {
        throw new Error('GCP KMS asymmetricSign response did not include signature');
      }

      if (typeof res.signature === 'string') {
        return Buffer.from(res.signature, 'base64');
      }
      return Buffer.from(res.signature);
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.KMS_OUTAGE,
        `GCP Cloud KMS Asymmetric Sign failed for key ${this.keyVersionName}: ${err.message}`
      );
    }
  }
}
