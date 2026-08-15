import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { SecurityFabricCoordinator } from '../../src/fabric/coordinator.js';
import { createSecurityEvent } from '../../src/fabric/events.js';
import { SentinelAdvisor } from '../../src/sentinel/advisor.js';
import { PolicyGate } from '../../src/sentinel/policy_gate.js';
import { WORMCheckpointStore } from '../../src/checkpoint/worm.js';
import { EvmAnchorAdapter } from '../../src/anchors/evm.js';
import { CheckpointAnchorEngine, computeCheckpointDigest } from '../../src/checkpoint/anchor.js';
import { RecoveryProvenanceEngine } from '../../src/engine/recovery_provenance.js';
import { encodeApprovalPayload, SignedApprovalEnvelope } from '../../src/crypto/approval.js';
import { RecoveryProposal } from '../../src/engine/recovery.js';

describe('Distributed Security Fabric Full Integration (v0.5 Integration)', () => {
  it('property: executes complete cross-layer defense from multi-plane telemetry to verified state recovery', async () => {
    // 1. Setup external trust layers
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });

    const checkpointId = '00000000-0000-0000-0000-000000002000';
    const scope = 'public.users';
    const commitSeq = 2000n;
    const createdAtUs = 1723500000000000n;
    const honestMerkleRoot = Buffer.alloc(32, 0x99);

    // Anchor authentic historical baseline checkpoint #2000
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

    // 2. Telemetry feeds from Database, Runtime, and AEGIS
    const coordinator = new SecurityFabricCoordinator();

    const dbEvent = createSecurityEvent({
      plane: 'DATABASE',
      eventType: 'DB_UNAUTHORIZED_MUTATION',
      actorId: 'dba_service_07',
      serviceId: 'pg_primary',
      scope,
      payload: { recordIds: ['rec-1'] },
    });

    const runtimeEvent = createSecurityEvent({
      plane: 'RUNTIME',
      eventType: 'RUNTIME_PRIVILEGE_ESCALATION',
      actorId: 'dba_service_07',
      serviceId: 'api_gateway',
      scope,
      payload: { attemptedRole: 'SUPERUSER' },
    });

    const aegisEvent = createSecurityEvent({
      plane: 'AEGIS_INTEL',
      eventType: 'AEGIS_THREAT_CORRELATION',
      actorId: 'dba_service_07',
      serviceId: 'aegis_analyzer',
      scope,
      payload: { threatActor: 'APT-SUSPECT' },
    });

    const { incidentId, graph } = coordinator.correlateEvent(dbEvent);
    graph.ingestSecurityEvent(runtimeEvent);
    graph.ingestSecurityEvent(aegisEvent);

    expect(graph.getNodeCount()).toBeGreaterThanOrEqual(4);

    // 3. Explainable Risk Calculation
    const signals = {
      stateIntegrity: { score: 90, evidence: 'Merkle root mismatch' },
      provenance: { score: 80, evidence: 'Privilege escalation in runtime' },
      behavioral: { score: 85, evidence: 'Out of window mutation' },
      historical: { score: 30, evidence: 'Low prior alert history' },
      externalIntel: { score: 90, evidence: 'AEGIS high confidence threat correlation' },
    };

    const { riskBreakdown, responseLevel } = coordinator.evaluateIncidentRisk(incidentId, signals);
    expect(riskBreakdown.compositeScore).toBeGreaterThanOrEqual(80);
    expect(responseLevel).toBe('LEVEL_4_REQUIRE_APPROVAL');

    const anomalyIncident = coordinator.synthesizeFabricAnomalyIncident(
      incidentId,
      dbEvent,
      riskBreakdown.compositeScore,
      'Multi-plane breach detected across Database, Runtime, and AEGIS'
    );

    // 4. Sentinel Advisor formulates Proposal
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
      anomalyIncident,
      checkpointId,
      'ver-2000',
      honestMerkleRoot,
      expectedAnchorDigest,
      affectedRecords,
      'Restore corrupted role back to verified Checkpoint #2000'
    );

    expect(advisoryProposal.decisionAuthority).toBe('NONE');

    // 5. Policy Gate evaluates Proposal
    const gateResult = await PolicyGate.evaluateProposal(
      advisoryProposal,
      vaultStore,
      evmAdapter,
      ['public.users']
    );

    expect(gateResult.allowed).toBe(true);
    expect(advisoryProposal.status).toBe('POLICY_APPROVED');

    // 6. Ed25519 Quorum Approver signs Proposal
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const approverPubkey = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    const trustedApprovers = [approverPubkey];
    const consumedNonces = new Set<string>();

    const envelopePayload = {
      incidentId: Buffer.alloc(16, 0x55),
      protectedScope: scope,
      targetVersionId: Buffer.alloc(16, 0x20),
      proposedChangesHash: advisoryProposal.proposedChangesHash,
      requesterId: 'sentinel_advisor_auto',
      approverPubkey,
      nonce: Buffer.alloc(16, 0x77),
      expiresAtUs: BigInt(Date.now() + 60000) * 1000n,
    };
    const signature = crypto.sign(null, encodeApprovalPayload(envelopePayload), privateKey);

    const signedEnvelope: SignedApprovalEnvelope = {
      ...envelopePayload,
      signature,
    };

    const recoveryProposalForEngine: RecoveryProposal = {
      proposalId: advisoryProposal.proposalId,
      incidentId: anomalyIncident.incidentId,
      protectedScope: scope,
      targetVersionId: 'ver-2000',
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

    // 7. Atomic Recovery Execution & New Anchor Emission
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

    const isAuditValid = await RecoveryProvenanceEngine.auditRecoveryLineage(
      auditTrail,
      trustedApprovers,
      vaultStore
    );
    expect(isAuditValid).toBe(true);
  });
});
