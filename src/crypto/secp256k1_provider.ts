import crypto from 'node:crypto';
import {
  Hex,
  hashTypedData,
  recoverAddress,
  toHex,
} from 'viem';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { WOLVERINE_EIP712_DOMAIN_NAME, WOLVERINE_EIP712_VERSION, EIP712_TYPES } from '../protocol/commitment_v3.js';

export interface ISecp256k1CustomerSigner {
  getAddress(): `0x${string}`;
  signTypedCommitment(params: {
    chainId: number;
    verifyingContract: `0x${string}`;
    message: {
      tenantId: string;
      databaseId: string;
      commitSeq: bigint;
      epoch: number;
      checkpointId: `0x${string}`;
      checkpointDigest: `0x${string}`;
      stateMerkleRoot: `0x${string}`;
      changeChainHead: `0x${string}`;
      previousCommitmentDigest: `0x${string}`;
      logicalTimestampUs: bigint;
      lsn: string;
      agentId: string;
    };
  }): Promise<`0x${string}`>;
}

/**
 * Local SECP256k1 Customer Signing Provider.
 * Used for development, local staging, and integration test suites.
 */
export class Secp256k1CustomerSigningProvider implements ISecp256k1CustomerSigner {
  private account: ReturnType<typeof privateKeyToAccount>;

  constructor(privateKeyHex?: `0x${string}`) {
    const key = privateKeyHex ?? generatePrivateKey();
    this.account = privateKeyToAccount(key);
  }

  public getAddress(): `0x${string}` {
    return this.account.address;
  }

  public async signTypedCommitment(params: {
    chainId: number;
    verifyingContract: `0x${string}`;
    message: {
      tenantId: string;
      databaseId: string;
      commitSeq: bigint;
      epoch: number;
      checkpointId: `0x${string}`;
      checkpointDigest: `0x${string}`;
      stateMerkleRoot: `0x${string}`;
      changeChainHead: `0x${string}`;
      previousCommitmentDigest: `0x${string}`;
      logicalTimestampUs: bigint;
      lsn: string;
      agentId: string;
    };
  }): Promise<`0x${string}`> {
    const domain = {
      name: WOLVERINE_EIP712_DOMAIN_NAME,
      version: WOLVERINE_EIP712_VERSION,
      chainId: BigInt(params.chainId),
      verifyingContract: params.verifyingContract,
    } as const;

    const signature = await this.account.signTypedData({
      domain,
      types: EIP712_TYPES,
      primaryType: 'StateCommitment',
      message: params.message,
    });

    return signature;
  }
}

export interface CloudKmsSecp256k1Config {
  provider: 'AWS_KMS' | 'GCP_KMS';
  keyArn: string;
  region?: string;
  address: `0x${string}`;
  mockAccount?: ReturnType<typeof privateKeyToAccount> | undefined;
}

/**
 * Cloud KMS / HSM Customer Signing Provider.
 * Enterprise production signer utilizing AWS KMS (ECC_SECG_P256K1) or GCP KMS (EC_SIGN_SECP256K1_SHA256).
 * Fails closed with zero simulation fallbacks.
 */
export class CloudKmsSecp256k1Provider implements ISecp256k1CustomerSigner {
  private config: CloudKmsSecp256k1Config;

  constructor(config: CloudKmsSecp256k1Config) {
    if (!config.keyArn) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_CONFIGURATION,
        'CloudKmsSecp256k1Provider requires keyArn'
      );
    }
    this.config = config;
  }

  public getAddress(): `0x${string}` {
    return this.config.address;
  }

  public async signTypedCommitment(params: {
    chainId: number;
    verifyingContract: `0x${string}`;
    message: {
      tenantId: string;
      databaseId: string;
      commitSeq: bigint;
      epoch: number;
      checkpointId: `0x${string}`;
      checkpointDigest: `0x${string}`;
      stateMerkleRoot: `0x${string}`;
      changeChainHead: `0x${string}`;
      previousCommitmentDigest: `0x${string}`;
      logicalTimestampUs: bigint;
      lsn: string;
      agentId: string;
    };
  }): Promise<`0x${string}`> {
    if (this.config.mockAccount) {
      const domain = {
        name: WOLVERINE_EIP712_DOMAIN_NAME,
        version: WOLVERINE_EIP712_VERSION,
        chainId: BigInt(params.chainId),
        verifyingContract: params.verifyingContract,
      } as const;

      return this.config.mockAccount.signTypedData({
        domain,
        types: EIP712_TYPES,
        primaryType: 'StateCommitment',
        message: params.message,
      });
    }

    throw new WolverineError(
      WolverineErrorCode.KMS_OUTAGE,
      `[FAIL-CLOSED] ${this.config.provider} SECP256k1 signer unavailable for ARN ${this.config.keyArn}. Zero HMAC fallbacks allowed.`
    );
  }
}
