import { createWalletClient, createPublicClient, http, custom, fallback, Hex } from 'viem';
import { base, baseSepolia } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { BlockchainAnchorProvider, CanonicalAnchorBatch } from './batch_anchor.js';
import { anchorRegistryAbi } from './contracts/anchor_registry_abi.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface BaseL2AnchorConfig {
  network: 'base-mainnet' | 'base-sepolia';
  rpcUrl?: string;
  privateKey: Hex;
  contractAddress: Hex;
}

export class BaseL2AnchorProvider implements BlockchainAnchorProvider {
  private publicClient;
  private walletClient;
  private account;
  private contractAddress: Hex;

  constructor(public readonly config: BaseL2AnchorConfig) {
    const chain = config.network === 'base-mainnet' ? base : baseSepolia;
    
    this.publicClient = createPublicClient({
      chain,
      transport: config.rpcUrl ? http(config.rpcUrl) : http(),
    });

    this.account = privateKeyToAccount(config.privateKey);

    this.walletClient = createWalletClient({
      account: this.account,
      chain,
      transport: config.rpcUrl ? http(config.rpcUrl) : http(),
    });

    this.contractAddress = config.contractAddress;
  }

  public async submitAnchor(
    batch: CanonicalAnchorBatch
  ): Promise<{ txHashHex: string; blockNumber: bigint; blockHashHex: string }> {
    let retries = 0;
    const maxRetries = 3;

    while (true) {
      try {
        const { request } = await this.publicClient.simulateContract({
          address: this.contractAddress,
          abi: anchorRegistryAbi,
          functionName: 'anchorBatch',
          args: [
            BigInt(batch.epoch),
            BigInt(batch.startLedgerSeq),
            BigInt(batch.endLedgerSeq),
            `0x${batch.batchRootHex}` as Hex,
            `0x${batch.previousAnchorRootHex}` as Hex,
          ],
          account: this.account,
        });

        const txHash = await this.walletClient.writeContract(request);
        
        const receipt = await this.publicClient.waitForTransactionReceipt({
          hash: txHash,
        });

        if (receipt.status !== 'success') {
          throw new WolverineError(
            WolverineErrorCode.ANCHOR_UNAVAILABLE,
            `Transaction reverted: ${txHash}`
          );
        }

        return {
          txHashHex: txHash.slice(2),
          blockNumber: receipt.blockNumber,
          blockHashHex: receipt.blockHash.slice(2),
        };
      } catch (error: any) {
        retries++;
        if (retries > maxRetries) {
          throw new WolverineError(
            WolverineErrorCode.ANCHOR_UNAVAILABLE,
            `Failed to submit anchor after ${maxRetries} retries: ${error.message}`
          );
        }
        // Exponential backoff
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, retries) * 1000));
      }
    }
  }

  public async checkStatus(txHashHex: string): Promise<{ confirmed: boolean; reorged: boolean; confirmations: number }> {
    try {
      const hash = `0x${txHashHex}` as Hex;
      const receipt = await this.publicClient.getTransactionReceipt({ hash });
      const currentBlock = await this.publicClient.getBlockNumber();
      
      const confirmations = Number(currentBlock - receipt.blockNumber) + 1;
      
      // Check for reorg by fetching the block and comparing block hash
      const block = await this.publicClient.getBlock({ blockNumber: receipt.blockNumber });
      
      if (block.hash !== receipt.blockHash) {
        return { confirmed: false, reorged: true, confirmations: 0 };
      }

      return {
        confirmed: true,
        reorged: false,
        confirmations: Math.max(0, confirmations),
      };
    } catch (error: any) {
      // If receipt not found, it might be pending or reorged entirely
      return { confirmed: false, reorged: false, confirmations: 0 };
    }
  }
}
