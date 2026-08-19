import crypto from 'node:crypto';
import { ISigningProvider, SigningProviderType } from './signing_provider.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface LocalDevelopmentSigningProviderOptions {
  privateKey?: crypto.KeyObject;
  keyId?: string;
  allowDevSigner?: boolean;
}

/**
 * Explicit Local Development Signing Provider.
 * MUST NOT be used in production. Requires explicit opt-in via WOLVERINE_DEV_SIGNER=1 or allowDevSigner=true.
 */
export class LocalDevelopmentSigningProvider implements ISigningProvider {
  private readonly keyId: string;
  private readonly privateKey: crypto.KeyObject;
  private readonly publicKeyBytes: Buffer;

  constructor(options: LocalDevelopmentSigningProviderOptions = {}) {
    const isDevEnvAllowed =
      options.allowDevSigner === true ||
      process.env.WOLVERINE_DEV_SIGNER === '1' ||
      process.env.NODE_ENV === 'test';

    if (!isDevEnvAllowed) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        'LocalDevelopmentSigningProvider rejected: development signer is NOT permitted in production without WOLVERINE_DEV_SIGNER=1'
      );
    }

    if (process.env.NODE_ENV !== 'test') {
      console.warn('\n⚠️  [WARN] DEVELOPMENT SIGNER ACTIVE — NOT KMS. DO NOT USE IN PRODUCTION.\n');
    }

    this.keyId = options.keyId ?? 'dev-local-customer-key-01';

    if (options.privateKey) {
      this.privateKey = options.privateKey;
    } else {
      const generated = crypto.generateKeyPairSync('ed25519');
      this.privateKey = generated.privateKey;
    }

    const pubKeyObj = crypto.createPublicKey(this.privateKey);
    this.publicKeyBytes = pubKeyObj.export({ type: 'spki', format: 'der' }).subarray(-32);
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
