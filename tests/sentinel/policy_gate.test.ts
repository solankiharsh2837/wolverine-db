import { describe, it, expect } from 'vitest';
import { PolicyGate } from '../../src/sentinel/policy_gate.js';
import { WORMCheckpointStore } from '../../src/checkpoint/worm.js';
import { EvmAnchorAdapter } from '../../src/anchors/evm.js';
import { CheckpointAnchorEngine, computeCheckpointDigest } from '../../src/checkpoint/anchor.js';
import { AdvisoryRecoveryProposal } from '../../src/sentinel/types.js';
import crypto from 'node:crypto';
import { canonicalizeJson } from '../../src/binary/c14n.js';

describe('Deterministic Policy Gate Engine (WDB-0034 Hardening)', () => {
  const registeredScopes = ['public.users', 'public.accounts'];
  const checkpointId = '00000000-0000-0000-0000-000000001842';
  const scope = 'public.users';
  const commitSeq = 1842n;
  const createdAtUs = 1723500000000000n;
  const merkleRoot = Buffer.alloc(32, 0x55);

  it('property: ALLOW_PROPOSAL when basis checkpoint, anchor digest, and scope bounds match', async () => {
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });

    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, {
      checkpointId,
      scope,
      commitSeq,
      previousCheckpointId: null,
      merkleRoot,
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs,
      protocolVersion: 3,
    });

    const anchorDigest = computeCheckpointDigest({
      checkpointId,
      scope,
      commitSeq,
      previousCheckpointId: null,
      merkleRoot,
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs,
      protocolVersion: 3,
    });
    await evmAdapter.anchorCheckpoint(checkpointId, anchorDigest, commitSeq);

    const affectedRecords = [
      {
        tableName: 'public.users',
        primaryKeyHex: '010203',
        fieldName: 'role',
        compromisedValue: 'SUPERUSER',
        restoredValue: 'USER',
      },
    ];
    const proposedChangesHash = crypto
      .createHash('sha256')
      .update(Buffer.from(canonicalizeJson(affectedRecords), 'utf8'))
      .digest();

    const proposal: AdvisoryRecoveryProposal = {
      proposalId: '00000000-0000-0000-0000-000000000184',
      incidentId: '00000000-0000-0000-0000-000000000491',
      protectedScope: scope,
      targetBasisVersionId: 'ver-1842',
      sourceCheckpointId: checkpointId,
      expectedMerkleRoot: merkleRoot,
      expectedAnchorDigest: anchorDigest,
      affectedRecords,
      proposedChangesHash,
      confidenceScore: 95,
      riskAssessment: 'LOW',
      rationale: 'Valid restoration',
      decisionAuthority: 'NONE',
      status: 'PENDING_POLICY_EVALUATION',
    };

    const gateResult = await PolicyGate.evaluateProposal(
      proposal,
      vaultStore,
      evmAdapter,
      registeredScopes
    );

    expect(gateResult.allowed).toBe(true);
    expect(gateResult.verdict).toBe('ALLOW_PROPOSAL');
    expect(proposal.status).toBe('POLICY_APPROVED');
  });

  it('property: REJECT_PROPOSAL if affected records breach scope or anchor does not match', async () => {
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });

    const affectedRecords = [
      {
        tableName: 'public.system_config', // Scope breach!
        primaryKeyHex: '010203',
        fieldName: 'admin_key',
        compromisedValue: 'x',
        restoredValue: 'y',
      },
    ];
    const proposedChangesHash = crypto
      .createHash('sha256')
      .update(Buffer.from(canonicalizeJson(affectedRecords), 'utf8'))
      .digest();

    const rogueProposal: AdvisoryRecoveryProposal = {
      proposalId: 'prop-rogue',
      incidentId: 'inc-rogue',
      protectedScope: 'public.users',
      targetBasisVersionId: 'ver-1',
      sourceCheckpointId: 'chk-nonexistent',
      expectedMerkleRoot: merkleRoot,
      expectedAnchorDigest: Buffer.alloc(32, 0),
      affectedRecords,
      proposedChangesHash,
      confidenceScore: 99,
      riskAssessment: 'HIGH',
      rationale: 'Rogue AI proposal attempting to modify system_config',
      decisionAuthority: 'NONE',
      status: 'PENDING_POLICY_EVALUATION',
    };

    await expect(
      PolicyGate.evaluateProposal(rogueProposal, vaultStore, evmAdapter, registeredScopes)
    ).rejects.toThrow('PolicyGate: Affected record table "public.system_config" breaches proposal scope');
  });
});
