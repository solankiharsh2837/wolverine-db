import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { BaselineTracker } from '../../src/sentinel/baseline.js';
import { SentinelAnomalyEngine } from '../../src/sentinel/anomaly_engine.js';
import { SentinelAdvisor } from '../../src/sentinel/advisor.js';
import { PolicyGate } from '../../src/sentinel/policy_gate.js';
import { WORMCheckpointStore } from '../../src/checkpoint/worm.js';
import { EvmAnchorAdapter } from '../../src/anchors/evm.js';
import { CheckpointAnchorEngine, computeCheckpointDigest } from '../../src/checkpoint/anchor.js';
import { RecoveryProvenanceEngine } from '../../src/engine/recovery_provenance.js';
import { encodeApprovalPayload, SignedApprovalEnvelope } from '../../src/crypto/approval.js';
import { RecoveryProposal } from '../../src/engine/recovery.js';

describe('Complete Policy-Gated Self-Healing Lifecycle (v0.4 Integration)', () => {
  it('property: executes end-to-end self-healing from DBA breach to verified re-anchored state', async () => {
    // 1. Setup external trust layers
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });

    const checkpointId = '00000000-0000-0000-0000-000000001842';
    const scope = 'public.users';
    const commitSeq = 1842n;
    const createdAtUs = 1723500000000000n;
    const honestMerkleRoot = Buffer.alloc(32, 0x88);

    // Anchor authentic historical baseline checkpoint #1842
    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, {
      checkpointId,
      scope,
      commitSeq,
      previousCheckpointId: null,
      merkleRoot: honestMerkleRoot,
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs,
      protocolVersion: 3,
    });

    const expectedAnchorDigest = computeCheckpointDigest({
      checkpointId,
      scope,
      commitSeq,
      previousCheckpointId: null,
      merkleRoot: honestMerkleRoot,
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs,
      protocolVersion: 3,
    });
    await evmAdapter.anchorCheckpoint(checkpointId, expectedAnchorDigest, commitSeq);

    // 2. Setup Sentinel Behavioral Baseline
    const tracker = new BaselineTracker();
    tracker.registerBaseline({
      actorId: 'dba_service_07',
      allowedScopes: ['public.users'],
      typicalOperations: [2],
      maintenanceWindows: [{ startUtcHour: 2, endUtcHour: 4, daysOfWeek: [0] }],
      maxMutationsPerMinute: 50,
      averageBatchSize: 5,
      requiresTicketProvenance: true,
    });

    const anomalyEngine = new SentinelAnomalyEngine(tracker);

    // 3. Attacker uses DBA account out-of-window to corrupt user records
    const incident = anomalyEngine.analyzeMutation({
      actorId: 'dba_service_07',
      serviceId: 'pg_direct_admin',
      scope: 'public.users',
      operation: 2,
      recordIds: ['rec-1', 'rec-2', 'rec-3'],
      utcHour: 15, // Out of window
      dayOfWeek: 3,
      mutationRatePerMin: 200, // Velocity spike (+20) -> Score = 35 + 25 + 20 = 80 (CRITICAL)
      // Missing ticket (+25)
    });

    expect(incident).not.toBeNull();
    expect(incident?.severity).toBe('CRITICAL');

    // 4. Sentinel Advisor formulates non-destructive Recovery Proposal
    const affectedRecords = [
      {
        tableName: 'public.users',
        primaryKeyHex: '01',
        fieldName: 'role',
        compromisedValue: 'SUPERUSER',
        restoredValue: 'USER',
      },
    ];

    const advisoryProposal = SentinelAdvisor.formulateRecoveryProposal(
      incident!,
      checkpointId,
      'ver-1842',
      honestMerkleRoot,
      expectedAnchorDigest,
      affectedRecords,
      'Compensating recovery of corrupted role permissions back to verified Checkpoint #1842'
    );

    expect(advisoryProposal.decisionAuthority).toBe('NONE');

    // 5. Deterministic Policy Gate evaluates proposal
    const gateResult = await PolicyGate.evaluateProposal(
      advisoryProposal,
      vaultStore,
      evmAdapter,
      ['public.users']
    );

    expect(gateResult.allowed).toBe(true);
    expect(advisoryProposal.status).toBe('POLICY_APPROVED');

    // 6. Multi-Party Ed25519 Approver signs the verified proposal
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const approverPubkey = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    const trustedApprovers = [approverPubkey];
    const consumedNonces = new Set<string>();

    const envelopePayload = {
      incidentId: Buffer.from(incident!.incidentId.replace(/-/g, ''), 'hex'),
      protectedScope: scope,
      targetVersionId: Buffer.alloc(16, 0x42),
      proposedChangesHash: advisoryProposal.proposedChangesHash,
      requesterId: 'sentinel_advisor_auto',
      approverPubkey,
      nonce: Buffer.alloc(16, 0x99),
      expiresAtUs: BigInt(Date.now() + 60000) * 1000n,
    };
    const signature = crypto.sign(null, encodeApprovalPayload(envelopePayload), privateKey);

    const signedEnvelope: SignedApprovalEnvelope = {
      ...envelopePayload,
      signature,
    };

    const recoveryProposalForEngine: RecoveryProposal = {
      proposalId: advisoryProposal.proposalId,
      incidentId: incident!.incidentId,
      protectedScope: scope,
      targetVersionId: 'ver-1842',
      proposedChangesHash: advisoryProposal.proposedChangesHash,
      requesterId: 'sentinel_advisor_auto',
      status: 'PENDING',
      proposedChanges: [
        {
          tableName: 'public.users',
          primaryKeyTuple: Buffer.from('01', 'hex'),
          fieldName: 'role',
          newValue: 'USER',
        },
      ],
    };

    // 7. Atomic Recovery Execution & New Checkpoint Re-Anchor
    const { result, auditTrail } = await RecoveryProvenanceEngine.executeWithProvenance(
      recoveryProposalForEngine,
      signedEnvelope,
      trustedApprovers,
      consumedNonces,
      vaultStore,
      commitSeq + 1n,
      honestMerkleRoot,
      checkpointId
    );

    expect(result.success).toBe(true);
    expect(auditTrail.auditStatus).toBe('PROVABLY_CORRECT');

    // Audit full historical lineage
    const isAuditValid = await RecoveryProvenanceEngine.auditRecoveryLineage(
      auditTrail,
      trustedApprovers,
      vaultStore
    );
    expect(isAuditValid).toBe(true);
  });
});
