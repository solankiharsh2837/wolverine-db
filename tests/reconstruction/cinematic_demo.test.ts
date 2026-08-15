import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WORMCheckpointStore,
  EvmAnchorAdapter,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  BaselineTracker,
  StateReconstructionCoordinator,
  ReconstructionCli,
} from '../../src/index.js';
import { MutationOperation, ChangeRecordData } from '../../src/protocol/types.js';

describe('Cinematic End-to-End State Reconstruction (09:00..10:04 Critical Scenario)', () => {
  it('property: reconstructs latest stable authorized state at 09:45, preserving all 4 legitimate changes and excluding all attacker changes', async () => {
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });

    const baselineTracker = new BaselineTracker();
    baselineTracker.registerBaseline({
      actorId: 'app_service_auth',
      allowedScopes: ['public.users'],
      typicalOperations: [1, 2],
      maintenanceWindows: [],
      maxMutationsPerMinute: 100,
      averageBatchSize: 5,
      requiresTicketProvenance: false,
    });

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

    const baseCheckpoint = {
      checkpointId: '00000000-0000-0000-0000-000000001842',
      scope: 'public.users',
      commitSeq: 42n,
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x18),
      changeChainHead: Buffer.alloc(32, 0x00),
      createdAtUs: 1723500000000000n, // 09:00
      protocolVersion: 3,
    };

    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, baseCheckpoint);
    const baseDigest = computeCheckpointDigest(baseCheckpoint);
    await evmAdapter.anchorCheckpoint(baseCheckpoint.checkpointId, baseDigest, baseCheckpoint.commitSeq);

    const user1Pk = Buffer.from('00000001', 'hex');
    const user2Pk = Buffer.from('00000002', 'hex');

    const changesAfterCheckpoint = [
      // 09:15 - Seq 43
      {
        data: {
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000043',
          transactionId: 'tx-0915',
          timestampUs: 1723500900000000n,
          tableId: 'public.users',
          recordId: user1Pk,
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 'user-1', name: 'Alice', balance: 100, role: 'USER' }, old: null },
          provenance: { actor: 'app_service_auth' },
          previousHash: Buffer.alloc(32, 0x00),
        } as ChangeRecordData,
        recordBytes: Buffer.from('rec-43'),
        computedHash: Buffer.alloc(32, 0x43),
        commitSeq: 43n,
        actorId: 'app_service_auth',
        utcHour: 9,
        dayOfWeek: 2,
      },
      // 09:30 - Seq 44
      {
        data: {
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000044',
          transactionId: 'tx-0930',
          timestampUs: 1723501800000000n,
          tableId: 'public.users',
          recordId: user2Pk,
          operation: MutationOperation.INSERT,
          fieldSet: { new: { id: 'user-2', name: 'Bob', balance: 250, role: 'USER' }, old: null },
          provenance: { actor: 'app_service_auth' },
          previousHash: Buffer.alloc(32, 0x43),
        } as ChangeRecordData,
        recordBytes: Buffer.from('rec-44'),
        computedHash: Buffer.alloc(32, 0x44),
        commitSeq: 44n,
        actorId: 'app_service_auth',
        utcHour: 9,
        dayOfWeek: 2,
      },
      // 09:45 - Seq 45
      {
        data: {
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000045',
          transactionId: 'tx-0945',
          timestampUs: 1723502700000000n,
          tableId: 'public.users',
          recordId: user1Pk,
          operation: MutationOperation.UPDATE,
          fieldSet: { new: { balance: 150 }, old: { balance: 100 } },
          provenance: { actor: 'app_service_auth' },
          previousHash: Buffer.alloc(32, 0x44),
        } as ChangeRecordData,
        recordBytes: Buffer.from('rec-45'),
        computedHash: Buffer.alloc(32, 0x45),
        commitSeq: 45n,
        actorId: 'app_service_auth',
        utcHour: 9,
        dayOfWeek: 2,
      },

      // 10:01 - Seq 46 (Attacker Breach)
      {
        data: {
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000046',
          transactionId: 'tx-1001-malicious',
          timestampUs: 1723503660000000n,
          tableId: 'public.users',
          recordId: user1Pk,
          operation: MutationOperation.UPDATE,
          fieldSet: { new: { balance: 9999999, role: 'SUPERUSER' }, old: { balance: 150, role: 'USER' } },
          provenance: { actor: 'attacker_compromised' },
          previousHash: Buffer.alloc(32, 0x45),
        } as ChangeRecordData,
        recordBytes: Buffer.from('rec-46'),
        computedHash: Buffer.alloc(32, 0x46),
        commitSeq: 46n,
        actorId: 'attacker_compromised',
        utcHour: 10,
        dayOfWeek: 2,
      },
      // 10:02 - Seq 47 (Attacker DELETE)
      {
        data: {
          formatVersion: 1,
          versionId: '00000000-0000-0000-0000-000000000047',
          transactionId: 'tx-1002-malicious',
          timestampUs: 1723503720000000n,
          tableId: 'public.users',
          recordId: user2Pk,
          operation: MutationOperation.DELETE,
          fieldSet: { new: null, old: { id: 'user-2' } },
          provenance: { actor: 'attacker_compromised' },
          previousHash: Buffer.alloc(32, 0x46),
        } as ChangeRecordData,
        recordBytes: Buffer.from('rec-47'),
        computedHash: Buffer.alloc(32, 0x47),
        commitSeq: 47n,
        actorId: 'attacker_compromised',
        utcHour: 10,
        dayOfWeek: 2,
      },
    ];

    const workflowOptions = {
      databaseId: 'pg-prod-ledger-01',
      tenantId: 'org-enterprise',
      baseCheckpoint,
      initialCheckpointState: new Map(),
      changesAfterCheckpoint,
      externalVaultStore: vaultStore,
      evmAnchorAdapter: evmAdapter,
      baselineTracker,
      compromisedActors: ['attacker_compromised'],
      registeredScopes: ['public.users'],
      approverKeys,
    };

    // 1. CLI Frontier query
    const frontierCliResult = await ReconstructionCli.executeFrontier(workflowOptions);
    expect(frontierCliResult.success).toBe(true);
    expect(frontierCliResult.output).toContain('Verified Frontier Seq:    45');

    // 2. Plan Reconstruction
    const { manifest, advisoryProposal, reconstructedState } =
      await StateReconstructionCoordinator.planReconstruction(workflowOptions);

    expect(manifest.replayedChangeIds).toHaveLength(3); // 09:15, 09:30, 09:45
    expect(manifest.excludedChangeIds).toHaveLength(2); // 10:01, 10:02
    expect(manifest.recoveryBoundary.lastValidCommitSeq).toBe(45n);

    // Verify reconstructed table contents
    const userTable = reconstructedState.get('public.users');
    expect(userTable).toBeDefined();
    const aliceRow = userTable?.get(user1Pk.toString('hex'));
    expect(aliceRow?.values.balance).toBe(150); // Preserved legitimate update!
    expect(aliceRow?.values.role).toBe('USER'); // Did not become SUPERUSER!

    const bobRow = userTable?.get(user2Pk.toString('hex'));
    expect(bobRow?.values.id).toBe('user-2'); // Bob was NOT deleted!

    // 3. Execute restoration and issue State Recovery Certificate
    const { certificate, terminalOutput } =
      await StateReconstructionCoordinator.executeVerifiedRestoration(
        workflowOptions,
        manifest,
        advisoryProposal
      );

    expect(certificate.policyApprovalStatus).toBe('PASS');
    expect(certificate.cryptographicVerificationStatus).toBe('PASS');
    expect(certificate.authorizedChangesPreservedCount).toBe(3);
    expect(certificate.unauthorizedChangesExcludedCount).toBe(2);
    expect(terminalOutput).toContain('STATE RECOVERY CERTIFICATE');
    expect(terminalOutput).toContain('Verified State Frontier:             CommitSeq 45');
  });
});
