import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WORMCheckpointStore,
  EvmAnchorAdapter,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  BaselineTracker,
  StateReconstructionCoordinator,
} from '../../src/index.js';

describe('Approval Quorum & Scope Safety (WDB-0061, WDB-0065)', () => {
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

  const setupEnv = async () => {
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });
    const baselineTracker = new BaselineTracker();
    baselineTracker.registerBaseline({
      actorId: 'authorized_app',
      allowedScopes: ['public.users'],
      typicalOperations: [1, 2],
      maintenanceWindows: [],
      maxMutationsPerMinute: 100,
      averageBatchSize: 5,
      requiresTicketProvenance: false,
    });

    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, baseCheckpoint);
    const digest = computeCheckpointDigest(baseCheckpoint);
    await evmAdapter.anchorCheckpoint(baseCheckpoint.checkpointId, digest, baseCheckpoint.commitSeq);

    const approverKeys = [
      (() => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        return { publicKey: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32), privateKey };
      })(),
      (() => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        return { publicKey: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32), privateKey };
      })(),
    ];

    return { vaultStore, evmAdapter, baselineTracker, approverKeys };
  };

  it('scenario 24: rejects recovery proposal when scope is unauthorized or expanded', async () => {
    const { vaultStore, evmAdapter, baselineTracker, approverKeys } = await setupEnv();

    const options = {
      databaseId: 'pg-prod-01',
      tenantId: 'tenant-1',
      baseCheckpoint,
      initialCheckpointState: new Map(),
      changesAfterCheckpoint: [],
      externalVaultStore: vaultStore,
      evmAnchorAdapter: evmAdapter,
      baselineTracker,
      registeredScopes: ['public.users'],
      approverKeys,
    };

    const { manifest, advisoryProposal } = await StateReconstructionCoordinator.planReconstruction(options);

    // Attacker tampers with proposal scope to include unapproved secrets table
    advisoryProposal.protectedScope = 'public.internal_secrets';

    await expect(
      StateReconstructionCoordinator.executeVerifiedRestoration(options, manifest, advisoryProposal)
    ).rejects.toThrow('PolicyGate: Scope "public.internal_secrets" is not in registered protected scopes');
  });

  it('scenario 22: fails closed when reconstruction proposal payload hash is tampered with', async () => {
    const { vaultStore, evmAdapter, baselineTracker, approverKeys } = await setupEnv();

    const options = {
      databaseId: 'pg-prod-01',
      tenantId: 'tenant-1',
      baseCheckpoint,
      initialCheckpointState: new Map(),
      changesAfterCheckpoint: [],
      externalVaultStore: vaultStore,
      evmAnchorAdapter: evmAdapter,
      baselineTracker,
      registeredScopes: ['public.users'],
      approverKeys,
    };

    const { manifest, advisoryProposal } = await StateReconstructionCoordinator.planReconstruction(options);

    // Attacker modifies proposal changes hash
    advisoryProposal.proposedChangesHash = Buffer.alloc(32, 0xff);

    await expect(
      StateReconstructionCoordinator.executeVerifiedRestoration(options, manifest, advisoryProposal)
    ).rejects.toThrow('PolicyGate: Recomputed proposed changes hash does not match proposal commitment');
  });
});
