import { describe, it, expect } from 'vitest';
import {
  WORMCheckpointStore,
  EvmAnchorAdapter,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  BaselineTracker,
  VerifiedStateFrontierEngine,
} from '../../src/index.js';

describe('External Vault & Blockchain Anchor Resilience (WDB-0060, WDB-0064)', () => {
  const baseCheckpoint = {
    checkpointId: '00000000-0000-0000-0000-000000001842',
    scope: 'public.users',
    commitSeq: 10n,
    previousCheckpointId: null,
    merkleRoot: Buffer.alloc(32, 0x10),
    changeChainHead: Buffer.alloc(32, 0x00),
    createdAtUs: 1723500000000000n,
    protocolVersion: 3,
  };

  it('scenario 13 & 20: fails closed when checkpoint does not exist in external WORM vault', async () => {
    const emptyVaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });
    const baselineTracker = new BaselineTracker();

    const result = await VerifiedStateFrontierEngine.calculateFrontier({
      baseCheckpoint,
      changesAfterCheckpoint: [],
      externalVaultStore: emptyVaultStore,
      evmAnchorAdapter: evmAdapter,
      baselineTracker,
    });

    expect(result.isFrontierValid).toBe(false);
    expect(result.compromiseReason).toContain('missing from external WORM vault');
  });

  it('scenario 14: fails closed when local checkpoint diverges from public blockchain anchor', async () => {
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });
    const baselineTracker = new BaselineTracker();

    // Store genuine checkpoint in vault
    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, baseCheckpoint);

    // Anchor differing digest on blockchain
    const corruptDigest = Buffer.alloc(32, 0xff);
    await evmAdapter.anchorCheckpoint(baseCheckpoint.checkpointId, corruptDigest, baseCheckpoint.commitSeq);

    const result = await VerifiedStateFrontierEngine.calculateFrontier({
      baseCheckpoint,
      changesAfterCheckpoint: [],
      externalVaultStore: vaultStore,
      evmAnchorAdapter: evmAdapter,
      baselineTracker,
    });

    expect(result.isFrontierValid).toBe(false);
    expect(result.compromiseReason).toContain('not verified on public blockchain anchor');
  });

  it('scenario 16: fails closed when local checkpoint metadata is modified by attacker', async () => {
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });
    const baselineTracker = new BaselineTracker();

    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, baseCheckpoint);
    const honestDigest = computeCheckpointDigest(baseCheckpoint);
    await evmAdapter.anchorCheckpoint(baseCheckpoint.checkpointId, honestDigest, baseCheckpoint.commitSeq);

    // Attacker modifies local checkpoint commit sequence
    const tamperedLocalCheckpoint = {
      ...baseCheckpoint,
      commitSeq: 9999n,
    };

    const result = await VerifiedStateFrontierEngine.calculateFrontier({
      baseCheckpoint: tamperedLocalCheckpoint,
      changesAfterCheckpoint: [],
      externalVaultStore: vaultStore,
      evmAnchorAdapter: evmAdapter,
      baselineTracker,
    });

    expect(result.isFrontierValid).toBe(false);
    expect(result.compromiseReason).toContain('diverges from external vault state');
  });
});
