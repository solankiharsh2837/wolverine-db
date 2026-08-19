import {
  createPublicClient,
  createWalletClient,
  http,
  PublicClient,
  WalletClient,
  defineChain,
  Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { WOLVERINE_TRUST_REGISTRY_ABI } from './contract_abi.js';
import {
  BesuNodeConfig,
  BesuStateCommitmentInput,
  BesuTransactionReceipt,
  BesuCommitmentResult,
} from './types.js';
import { WolverineError, WolverineErrorCode } from '../../errors/index.js';

export class BesuClient {
  public readonly config: BesuNodeConfig;
  private publicClient?: PublicClient;
  private walletClient?: WalletClient;
  private customRpcHandler?: (method: string, params: any[]) => Promise<any>;

  constructor(config: BesuNodeConfig, customRpcHandler?: (method: string, params: any[]) => Promise<any>) {
    this.config = config;
    this.customRpcHandler = customRpcHandler;

    if (!customRpcHandler && config.rpcUrl) {
      const chain = defineChain({
        id: config.chainId,
        name: 'Wolverine Trust Chain',
        nativeCurrency: { name: 'Wolverine Gas', symbol: 'WGAS', decimals: 18 },
        rpcUrls: {
          default: { http: [config.rpcUrl] },
        },
      });

      this.publicClient = createPublicClient({
        chain,
        transport: http(config.rpcUrl, { timeout: config.timeoutMs ?? 5000 }),
      });

      if (config.operatorPrivateKeyHex) {
        const account = privateKeyToAccount(config.operatorPrivateKeyHex);
        this.walletClient = createWalletClient({
          account,
          chain,
          transport: http(config.rpcUrl, { timeout: config.timeoutMs ?? 5000 }),
        });
      }
    }
  }

  /**
   * Submits a dual-signed database state commitment directly to the WolverineTrustRegistry on Besu.
   */
  public async submitCommitment(
    input: BesuStateCommitmentInput
  ): Promise<BesuCommitmentResult> {
    const padHex32 = (hex: string): `0x${string}` => {
      const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
      return `0x${clean.padStart(64, '0')}`;
    };

    const padHex16 = (hex: string): `0x${string}` => {
      const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
      return `0x${clean.padStart(32, '0')}`;
    };

    const formatBytes = (hex: string): `0x${string}` => {
      const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
      return `0x${clean}`;
    };

    if (this.customRpcHandler) {
      const mockRes = await this.customRpcHandler('commitState', [input]);
      return mockRes;
    }

    if (!this.walletClient || !this.publicClient) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_CONFIGURATION,
        'BesuClient requires walletClient and publicClient to submit transactions'
      );
    }

    try {
      const { request } = await this.publicClient.simulateContract({
        account: this.walletClient.account,
        address: this.config.contractAddress,
        abi: WOLVERINE_TRUST_REGISTRY_ABI,
        functionName: 'commitState',
        args: [
          input.tenantId,
          input.databaseId,
          padHex16(input.checkpointIdHex),
          input.commitSeq,
          input.epoch,
          padHex32(input.checkpointDigestHex),
          padHex32(input.stateMerkleRootHex),
          padHex32(input.changeChainHeadHex),
          padHex32(input.previousCommitmentDigestHex),
          padHex32(input.commitmentDigestHex),
          input.logicalTimestampUs,
          input.protocolVersion,
          formatBytes(input.agentSignatureHex),
          formatBytes(input.customerSignatureHex),
        ],
      });

      const txHash = await this.walletClient.writeContract(request);
      const receipt = await this.publicClient.waitForTransactionReceipt({
        hash: txHash,
        confirmations: 1,
      });

      if (receipt.status === 'reverted') {
        throw new WolverineError(
          WolverineErrorCode.HISTORY_MUTATION_DETECTED,
          `Besu transaction reverted for commitment ${input.commitmentDigestHex}`
        );
      }

      return {
        success: true,
        txHash: receipt.transactionHash,
        blockNumber: receipt.blockNumber,
        blockHash: receipt.blockHash,
        commitmentDigestHex: input.commitmentDigestHex,
        contractAddress: this.config.contractAddress,
      };
    } catch (err: any) {
      throw new WolverineError(
        WolverineErrorCode.NETWORK_ERROR,
        `Failed to submit commitment to Besu: ${err.message}`
      );
    }
  }

  /**
   * Fetches on-chain commitment by its unique commitmentDigest.
   */
  public async getOnChainCommitment(commitmentDigestHex: string): Promise<any> {
    const padHex32 = (hex: string): `0x${string}` => {
      const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
      return `0x${clean.padStart(64, '0')}`;
    };

    if (this.customRpcHandler) {
      return this.customRpcHandler('getCommitment', [commitmentDigestHex]);
    }

    if (!this.publicClient) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_CONFIGURATION,
        'BesuClient publicClient not configured'
      );
    }

    return this.publicClient.readContract({
      address: this.config.contractAddress,
      abi: WOLVERINE_TRUST_REGISTRY_ABI,
      functionName: 'getCommitment',
      args: [padHex32(commitmentDigestHex)],
    });
  }

  /**
   * Queries latest block number from Besu.
   */
  public async getBlockNumber(): Promise<bigint> {
    if (this.customRpcHandler) {
      return this.customRpcHandler('eth_blockNumber', []);
    }
    if (!this.publicClient) return 0n;
    return this.publicClient.getBlockNumber();
  }

  /**
   * Queries connected peer count from Besu node.
   */
  public async getPeerCount(): Promise<number> {
    if (this.customRpcHandler) {
      return this.customRpcHandler('net_peerCount', []);
    }
    if (!this.publicClient) return 0;
    try {
      const countHex = await (this.publicClient as any).request({ method: 'net_peerCount' });
      return parseInt(countHex, 16);
    } catch {
      return 0;
    }
  }

  /**
   * Checks if Besu RPC is reachable and responsive.
   */
  public async isHealthy(): Promise<boolean> {
    try {
      const block = await this.getBlockNumber();
      return block >= 0n;
    } catch {
      return false;
    }
  }

  /**
   * Gets deployed bytecode for an address.
   */
  public async getCode(address: `0x${string}`): Promise<`0x${string}` | undefined> {
    if (this.customRpcHandler) {
      return this.customRpcHandler('eth_getCode', [address]);
    }
    if (!this.publicClient) return undefined;
    return this.publicClient.getBytecode({ address });
  }
}
