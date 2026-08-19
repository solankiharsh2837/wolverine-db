import crypto from 'node:crypto';
import { computeCustomerAuthorizationDigest } from '../trust/commitment.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface ICustomerSigner {
  readonly keyId: string;
  readonly publicKey: Buffer;
  signCommitment(commitmentDigest: Buffer, commitSeq: bigint): Promise<Buffer>;
}

export class SoftwareCustomerSigner implements ICustomerSigner {
  public readonly keyId: string;
  public readonly publicKey: Buffer;
  private privateKey: crypto.KeyObject;

  constructor(keyId: string, privateKey: crypto.KeyObject) {
    this.keyId = keyId;
    this.privateKey = privateKey;
    const pubKeyObject = crypto.createPublicKey(privateKey);
    this.publicKey = pubKeyObject.export({ format: 'der', type: 'spki' });
  }

  public async signCommitment(commitmentDigest: Buffer, commitSeq: bigint): Promise<Buffer> {
    const authDigest = computeCustomerAuthorizationDigest(commitmentDigest, commitSeq);
    return crypto.sign(null, authDigest, this.privateKey);
  }
}

export interface CloudKmsConfig {
  keyArn: string;
  kmsClient?: {
    asymmetricSign: (params: { KeyId: string; Message: Buffer; MessageType: string; SigningAlgorithm: string }) => Promise<{ Signature?: Uint8Array }>;
  };
}

export class CloudKmsCustomerSigner implements ICustomerSigner {
  public readonly keyId: string;
  public readonly publicKey: Buffer;
  private config: CloudKmsConfig;

  constructor(config: CloudKmsConfig, publicKey: Buffer) {
    this.keyId = config.keyArn;
    this.publicKey = publicKey;
    this.config = config;
  }

  public async signCommitment(commitmentDigest: Buffer, commitSeq: bigint): Promise<Buffer> {
    const authDigest = computeCustomerAuthorizationDigest(commitmentDigest, commitSeq);

    if (!this.config.kmsClient) {
      throw new WolverineError(
        WolverineErrorCode.MISSING_SECRET_KEY,
        `[FAIL_CLOSED] Cloud KMS client unavailable for Key "${this.config.keyArn}". System refusing fallback to local/insecure signatures.`
      );
    }

    try {
      const response = await this.config.kmsClient.asymmetricSign({
        KeyId: this.config.keyArn,
        Message: authDigest,
        MessageType: 'DIGEST',
        SigningAlgorithm: 'ED25519',
      });

      if (!response.Signature) {
        throw new WolverineError(
          WolverineErrorCode.MISSING_SECRET_KEY,
          `Cloud KMS returned empty signature for Key "${this.config.keyArn}"`
        );
      }

      return Buffer.from(response.Signature);
    } catch (err: any) {
      if (err instanceof WolverineError) throw err;
      throw new WolverineError(
        WolverineErrorCode.MISSING_SECRET_KEY,
        `[FAIL_CLOSED] Cloud KMS asymmetricSign failed: ${err.message}. Refusing fallback.`,
        { cause: err }
      );
    }
  }
}
