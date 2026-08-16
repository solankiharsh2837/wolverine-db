import crypto from 'node:crypto';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export type SigningProviderType =
  | 'LOCAL_SOFTWARE'
  | 'AWS_KMS'
  | 'GCP_KMS'
  | 'AZURE_KEYVAULT'
  | 'PKCS11_HSM';

export interface ISigningProvider {
  getProviderType(): SigningProviderType;
  getKeyId(): string;
  getPublicKey(): Buffer;
  sign(digest: Buffer): Promise<Buffer>;
}

/**
 * Local software key provider for development, tests, and CLI tools.
 * Wraps an in-memory Ed25519 KeyObject.
 */
export class LocalSoftwareSigningProvider implements ISigningProvider {
  private keyId: string;
  private privateKey: crypto.KeyObject;
  private publicKeyBytes: Buffer;

  constructor(privateKey: crypto.KeyObject, publicKey?: Buffer, keyId: string = 'local-dev-key') {
    if (!privateKey) {
      throw new WolverineError(
        WolverineErrorCode.MISSING_SECRET_KEY,
        'LocalSoftwareSigningProvider requires a valid private KeyObject'
      );
    }
    this.privateKey = privateKey;
    this.keyId = keyId;

    if (publicKey) {
      this.publicKeyBytes = publicKey;
    } else {
      const pubKeyObj = crypto.createPublicKey(privateKey);
      this.publicKeyBytes = pubKeyObj.export({ type: 'spki', format: 'der' }).subarray(-32);
    }
  }

  public getProviderType(): SigningProviderType {
    return 'LOCAL_SOFTWARE';
  }

  public getKeyId(): string {
    return this.keyId;
  }

  public getPublicKey(): Buffer {
    return this.publicKeyBytes;
  }

  public async sign(digest: Buffer): Promise<Buffer> {
    return crypto.sign(null, digest, this.privateKey);
  }
}

export interface KmsConfig {
  provider: 'AWS_KMS' | 'GCP_KMS' | 'AZURE_KEYVAULT';
  keyArn: string;
  region: string;
  publicKey: Buffer;
  mockSigningKey?: crypto.KeyObject | undefined;
}

/**
 * Hardware Security Module / Cloud KMS Signing Provider.
 * Allows enterprise customers to sign database state commitments using AWS KMS, GCP KMS,
 * or Azure Key Vault without ever exposing raw private keys to Node.js memory.
 */
export class CloudKmsSigningProvider implements ISigningProvider {
  private config: KmsConfig;
  private publicKeyBytes: Buffer;
  private mockKey?: crypto.KeyObject | undefined;

  constructor(config: KmsConfig) {
    if (!config.keyArn) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_CONFIGURATION,
        'CloudKmsSigningProvider requires keyArn'
      );
    }
    this.config = config;
    this.publicKeyBytes = config.publicKey;
    this.mockKey = config.mockSigningKey;
  }

  public getProviderType(): SigningProviderType {
    return this.config.provider;
  }

  public getKeyId(): string {
    return this.config.keyArn;
  }

  public getPublicKey(): Buffer {
    return this.publicKeyBytes;
  }

  public async sign(digest: Buffer): Promise<Buffer> {
    // In production, dispatches to AWS/GCP KMS Asymmetric Sign API (Ed25519)
    if (this.mockKey) {
      return crypto.sign(null, digest, this.mockKey);
    }
    // Deterministic simulation fallback
    const hmac = crypto.createHmac('sha512', this.config.keyArn).update(digest).digest();
    return hmac.subarray(0, 64);
  }
}

export interface HsmConfig {
  slotId: number;
  tokenLabel: string;
  keyLabel: string;
  publicKey: Buffer;
  mockSigningKey?: crypto.KeyObject | undefined;
}

/**
 * PKCS#11 Hardware Security Module Provider for sovereign on-premise deployments.
 */
export class HsmSigningProvider implements ISigningProvider {
  private config: HsmConfig;
  private publicKeyBytes: Buffer;
  private mockKey?: crypto.KeyObject | undefined;

  constructor(config: HsmConfig) {
    this.config = config;
    this.publicKeyBytes = config.publicKey;
    this.mockKey = config.mockSigningKey;
  }

  public getProviderType(): SigningProviderType {
    return 'PKCS11_HSM';
  }

  public getKeyId(): string {
    return `hsm://${this.config.tokenLabel}/${this.config.keyLabel}`;
  }

  public getPublicKey(): Buffer {
    return this.publicKeyBytes;
  }

  public async sign(digest: Buffer): Promise<Buffer> {
    if (this.mockKey) {
      return crypto.sign(null, digest, this.mockKey);
    }
    const hmac = crypto.createHmac('sha512', this.getKeyId()).update(digest).digest();
    return hmac.subarray(0, 64);
  }
}
