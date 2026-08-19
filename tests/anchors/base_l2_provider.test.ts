import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BaseL2AnchorProvider } from '../../src/anchors/base_l2_provider.js';
import { CanonicalAnchorBatch } from '../../src/anchors/batch_anchor.js';
import { WolverineError } from '../../src/errors/index.js';

vi.mock('viem', async (importOriginal) => {
  const actual = await importOriginal<typeof import('viem')>();
  return {
    ...actual,
    createPublicClient: vi.fn(),
    createWalletClient: vi.fn(),
  };
});

import { createPublicClient, createWalletClient } from 'viem';

describe('BaseL2AnchorProvider', () => {
  const mockConfig = {
    network: 'base-sepolia' as const,
    privateKey: '0x1234567890123456789012345678901234567890123456789012345678901234' as const,
    contractAddress: '0x1234567890123456789012345678901234567890' as const,
  };

  let mockPublicClient: any;
  let mockWalletClient: any;
  let provider: BaseL2AnchorProvider;

  beforeEach(() => {
    vi.clearAllMocks();

    mockPublicClient = {
      simulateContract: vi.fn(),
      waitForTransactionReceipt: vi.fn(),
      getTransactionReceipt: vi.fn(),
      getBlockNumber: vi.fn(),
      getBlock: vi.fn(),
    };

    mockWalletClient = {
      writeContract: vi.fn(),
    };

    (createPublicClient as any).mockReturnValue(mockPublicClient);
    (createWalletClient as any).mockReturnValue(mockWalletClient);

    provider = new BaseL2AnchorProvider(mockConfig);
  });

  it('constructs provider with config', () => {
    expect(provider.config).toEqual(mockConfig);
  });

  it('submits anchor batch successfully', async () => {
    const batch: CanonicalAnchorBatch = {
      networkId: 'base-sepolia',
      epoch: 1,
      startLedgerSeq: 1n,
      endLedgerSeq: 10n,
      ledgerStateRootHex: '1111',
      previousAnchorRootHex: '0000',
      batchRootHex: '2222',
      validatorSetId: 'val1',
      anchorVersion: 2,
      createdAtUs: 1000n,
      anchorBatchDigestHex: '3333'
    };

    mockPublicClient.simulateContract.mockResolvedValue({ request: {} });
    mockWalletClient.writeContract.mockResolvedValue('0xabcd1234');
    mockPublicClient.waitForTransactionReceipt.mockResolvedValue({
      status: 'success',
      blockNumber: 100n,
      blockHash: '0xblockhash123'
    });

    const res = await provider.submitAnchor(batch);

    expect(res).toEqual({
      txHashHex: 'abcd1234',
      blockNumber: 100n,
      blockHashHex: 'blockhash123'
    });
    
    expect(mockPublicClient.simulateContract).toHaveBeenCalled();
    expect(mockWalletClient.writeContract).toHaveBeenCalled();
  });

  it('handles transaction revert error', async () => {
    vi.useFakeTimers();
    const batch: CanonicalAnchorBatch = {
      networkId: 'base-sepolia',
      epoch: 1,
      startLedgerSeq: 1n,
      endLedgerSeq: 10n,
      ledgerStateRootHex: '1111',
      previousAnchorRootHex: '0000',
      batchRootHex: '2222',
      validatorSetId: 'val1',
      anchorVersion: 2,
      createdAtUs: 1000n,
      anchorBatchDigestHex: '3333'
    };

    mockPublicClient.simulateContract.mockResolvedValue({ request: {} });
    mockWalletClient.writeContract.mockResolvedValue('0xabcd1234');
    mockPublicClient.waitForTransactionReceipt.mockResolvedValue({
      status: 'reverted',
    });

    const promise = provider.submitAnchor(batch).catch(e => e);
    await vi.runAllTimersAsync();
    const err = await promise;
    expect(err).toBeInstanceOf(WolverineError);
    vi.useRealTimers();
  });
});
