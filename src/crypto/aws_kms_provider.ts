import crypto from 'node:crypto';
import { ISigningProvider, SigningProviderType } from './signing_provider.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface AwsKmsClientInterface {
  sign(params: {
    KeyId: string;
    Message: Uint8Array;
    MessageType: 'RAW' | 'DIGEST';
    SigningAlgorithm: string;
  }): Promise<{ Signature?: Uint8Array }>;
  getPublicKey(params: {
    KeyId: string;
  }): Promise<{ PublicKey?: Uint8Array }>;
}

export interface AwsKmsSigningProviderOptions {
  keyId: string; // Key ARN or Key ID / Alias
  region?: string;
  kmsClient?: AwsKmsClientInterface;
  publicKey?: Buffer;
  signingAlgorithm?: string; // Default: 'ED25519_SHA_512' or 'ECDSA_SHA_256'
  mockSigningKey?: crypto.KeyObject;
}

/**
 * Enterprise AWS KMS Signing Provider implementing ISigningProvider.
 * Issues cryptographic signatures over digests using AWS KMS Asymmetric Keys (e.g. ECC_NIST_ED25519 or ECC_NIST_P256).
 */
export class AwsKmsSigningProvider implements ISigningProvider {
  private readonly keyId: string;
  private readonly region: string;
  private readonly kmsClient?: AwsKmsClientInterface;
  private publicKeyBytes: Buffer;
  private readonly signingAlgorithm: string;
  private readonly mockSigningKey?: crypto.KeyObject;

  constructor(options: AwsKmsSigningProviderOptions) {
    if (!options.keyId) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_CONFIGURATION,
        'AwsKmsSigningProvider requires a valid keyId/ARN'
      );
    }
    this.keyId = options.keyId;
    this.region = options.region ?? 'us-east-1';
    this.kmsClient = options.kmsClient;
    this.signingAlgorithm = options.signingAlgorithm ?? 'ECDSA_SHA_256';
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
    return 'AWS_KMS';
  }

  public getKeyId(): string {
    return this.keyId;
  }

  public getRegion(): string {
    return this.region;
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
      const res = await this.kmsClient.getPublicKey({ KeyId: this.keyId });
      if (res.PublicKey) {
        this.publicKeyBytes = Buffer.from(res.PublicKey);
        return this.publicKeyBytes;
      }
      throw new Error('KMS getPublicKey returned empty response');
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.KMS_OUTAGE,
        `AWS KMS failed to fetch public key for ${this.keyId}: ${err.message}`
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
        `AWS KMS provider unconfigured: no live AWS KMS client or mock signing key provided for key ${this.keyId}`
      );
    }

    try {
      const res = await this.kmsClient.sign({
        KeyId: this.keyId,
        Message: new Uint8Array(digest),
        MessageType: 'DIGEST',
        SigningAlgorithm: this.signingAlgorithm,
      });

      if (!res.Signature) {
        throw new Error('KMS Sign response did not include Signature');
      }

      return Buffer.from(res.Signature);
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.KMS_OUTAGE,
        `AWS KMS Asymmetric Sign failed for key ${this.keyId}: ${err.message}`
      );
    }
  }
}
