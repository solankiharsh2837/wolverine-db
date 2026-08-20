import { createPublicClient, http, PublicClient, defineChain } from 'viem';
import { WolverineError, WolverineErrorCode } from '../../errors/index.js';

export interface BesuRpcNodeConfig {
  url: string;
  weight?: number;
}

export interface BesuRpcPoolOptions {
  nodes: (string | BesuRpcNodeConfig)[];
  chainId: number;
  timeoutMs?: number;
  maxRetries?: number;
  retryBackoffMs?: number;
  customRpcHandler?: (method: string, params: any[]) => Promise<any>;
}

export interface NodeHealthStatus {
  url: string;
  isHealthy: boolean;
  blockNumber: bigint;
  peerCount: number;
  latencyMs: number;
  consecutiveFailures: number;
  lastCheckedUs: bigint;
}

export class BesuRpcPool {
  private nodes: Array<{ url: string; weight: number }>;
  private health: Map<string, NodeHealthStatus> = new Map();
  private currentIndex: number = 0;
  private chainId: number;
  private timeoutMs: number;
  private maxRetries: number;
  private retryBackoffMs: number;
  private customRpcHandler?: (method: string, params: any[]) => Promise<any>;

  constructor(options: BesuRpcPoolOptions) {
    if (!options.nodes || options.nodes.length === 0) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_CONFIGURATION,
        'BesuRpcPool requires at least one RPC node'
      );
    }

    this.chainId = options.chainId;
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.maxRetries = options.maxRetries ?? 3;
    this.retryBackoffMs = options.retryBackoffMs ?? 200;
    this.customRpcHandler = options.customRpcHandler;

    this.nodes = options.nodes.map((n) =>
      typeof n === 'string' ? { url: n, weight: 1 } : { url: n.url, weight: n.weight ?? 1 }
    );

    for (const node of this.nodes) {
      this.health.set(node.url, {
        url: node.url,
        isHealthy: true,
        blockNumber: 0n,
        peerCount: 0,
        latencyMs: 0,
        consecutiveFailures: 0,
        lastCheckedUs: 0n,
      });
    }
  }

  public getHealthyNodes(): string[] {
    return this.nodes
      .filter((n) => this.health.get(n.url)?.isHealthy !== false)
      .map((n) => n.url);
  }

  public getAllNodes(): string[] {
    return this.nodes.map((n) => n.url);
  }

  public getNodeStatus(url: string): NodeHealthStatus | undefined {
    return this.health.get(url);
  }

  public getNextNodeUrl(): string {
    const healthy = this.getHealthyNodes();
    const list = healthy.length > 0 ? healthy : this.getAllNodes();
    const url = list[this.currentIndex % list.length]!;
    this.currentIndex = (this.currentIndex + 1) % list.length;
    return url;
  }

  public createClientForNode(rpcUrl: string): PublicClient {
    const customChain = defineChain({
      id: this.chainId,
      name: 'wolverine-trust-chain',
      nativeCurrency: { name: 'Wolverine Trust Gas', symbol: 'WTG', decimals: 18 },
      rpcUrls: { default: { http: [rpcUrl] } },
    });

    return createPublicClient({
      chain: customChain,
      transport: http(rpcUrl, { timeout: this.timeoutMs }),
    });
  }

  /**
   * Executes an RPC operation across healthy nodes with automatic failover and exponential retry.
   */
  public async executeWithFailover<T>(
    operation: (rpcUrl: string, client: PublicClient) => Promise<T>
  ): Promise<T> {
    if (this.customRpcHandler) {
      return operation('custom://mock', null as any);
    }

    let lastError: any = null;
    const attemptedUrls = new Set<string>();

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      const rpcUrl = this.getNextNodeUrl();
      attemptedUrls.add(rpcUrl);
      const client = this.createClientForNode(rpcUrl);
      const startMs = Date.now();

      try {
        const result = await operation(rpcUrl, client);
        const latency = Date.now() - startMs;

        // Record successful invocation
        const status = this.health.get(rpcUrl);
        if (status) {
          status.isHealthy = true;
          status.consecutiveFailures = 0;
          status.latencyMs = latency;
          status.lastCheckedUs = BigInt(Date.now()) * 1000n;
        }

        return result;
      } catch (err: any) {
        lastError = err;

        // If error is an EVM contract execution revert, do not retry other nodes (it will revert on all)
        const errMsg = String(err?.message || '');
        if (
          errMsg.includes('revert') ||
          errMsg.includes('Execution reverted') ||
          errMsg.includes('SequenceGapDetected') ||
          errMsg.includes('DuplicateCommitment') ||
          errMsg.includes('Unauthorized') ||
          errMsg.includes('InvalidCustomerSignature')
        ) {
          throw err;
        }

        // Record failure for this RPC node
        const status = this.health.get(rpcUrl);
        if (status) {
          status.consecutiveFailures++;
          if (status.consecutiveFailures >= 2) {
            status.isHealthy = false;
          }
        }

        // Exponential backoff before next attempt
        const backoff = this.retryBackoffMs * Math.pow(2, attempt);
        await new Promise((resolve) => setTimeout(resolve, backoff));
      }
    }

    throw new WolverineError(
      WolverineErrorCode.NETWORK_ERROR,
      `BesuRpcPool exhausted retries across nodes [${Array.from(attemptedUrls).join(', ')}]. Last error: ${lastError?.message}`
    );
  }

  /**
   * Proactively inspects health and block height of all nodes.
   */
  public async probeAllNodes(): Promise<NodeHealthStatus[]> {
    const results: NodeHealthStatus[] = [];

    for (const node of this.nodes) {
      const client = this.createClientForNode(node.url);
      const start = Date.now();
      try {
        const block = await client.getBlockNumber();
        let peers = 0;
        try {
          const peerHex = await (client as any).request({ method: 'net_peerCount' });
          peers = parseInt(peerHex, 16);
        } catch {
          // ignore peer count query failure
        }
        const latency = Date.now() - start;

        const stat: NodeHealthStatus = {
          url: node.url,
          isHealthy: true,
          blockNumber: block,
          peerCount: peers,
          latencyMs: latency,
          consecutiveFailures: 0,
          lastCheckedUs: BigInt(Date.now()) * 1000n,
        };
        this.health.set(node.url, stat);
        results.push(stat);
      } catch {
        const stat: NodeHealthStatus = {
          url: node.url,
          isHealthy: false,
          blockNumber: 0n,
          peerCount: 0,
          latencyMs: 0,
          consecutiveFailures: (this.health.get(node.url)?.consecutiveFailures ?? 0) + 1,
          lastCheckedUs: BigInt(Date.now()) * 1000n,
        };
        this.health.set(node.url, stat);
        results.push(stat);
      }
    }

    return results;
  }
}
