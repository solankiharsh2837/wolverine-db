import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  validateAndNormalizeDecimal,
  encodeBinaryRecord,
  decodeBinaryRecord,
  MerkleTree,
  EMPTY_TREE_ROOT,
  verifyMerkleProof,
  encodeApprovalPayload,
  verifyApprovalEnvelope,
  computeAttestationDigest,
  TrustValidator,
  PortableTrustProofGenerator,
  OfflineTrustProofVerifier,
  createSignedCustomerCommitment,
  ImmutableTrustReceiptGenerator,
  ImmutableTrustReceiptVerifier,
  ReceiptChain,
  EpochRotationManager,
  CustomerKeyRotationManager,
  PersistentTrustLedger,
  FederatedConsensusEngine,
  NodeRegistry,
  IncidentCorrelationGraph,
  StateDependencyGraphBuilder,
  StateReplayEngine,
  VerifiedStateFrontierEngine,
  EvmAnchorAdapter,
  AnchorStatus,
  matchesProtectedScope,
  WORMCheckpointStore,
  CheckpointAnchorEngine,
  computeCheckpointDigest,
  WolverineTrustNetworkService,
  WolverineEvidenceAgent,
  computeQuorumCertificateDigest,
  WolverineErrorCode,
  MutationOperation,
} from '../../src/index.js';

describe('Open GitHub Issues Regression Suite (#10 - #31)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('Issue #29: validateAndNormalizeDecimal strips trailing fractional zeros', () => {
    expect(validateAndNormalizeDecimal('1.50')).toBe('1.5');
    expect(validateAndNormalizeDecimal('1.500')).toBe('1.5');
    expect(validateAndNormalizeDecimal('10.00')).toBe('10');
    expect(validateAndNormalizeDecimal('0.100')).toBe('0.1');
    expect(validateAndNormalizeDecimal('-2.40')).toBe('-2.4');
  });

  it('Issue #26: decodeBinaryRecord rejects trailing bytes', () => {
    const field = { tag: 1, typeTag: 2, payload: Buffer.alloc(8, 1) };
    const validBuf = encodeBinaryRecord(1, [field]);
    const malformedBuf = Buffer.concat([validBuf, Buffer.from('extra_garbage')]);

    expect(() => decodeBinaryRecord(malformedBuf)).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.MALFORMED_FIELD_PAYLOAD })
    );
  });

  it('Issue #15: verifyMerkleProof fails closed on invalid side values', () => {
    const leaf = Buffer.from('leaf_payload', 'utf8');
    const tree = new MerkleTree([leaf, Buffer.from('sibling', 'utf8')]);
    const proof = tree.generateProof(0);

    // Invalid side = 2
    const invalidProofSteps = [{ siblingHash: proof.proof[0]!.siblingHash, side: 2 as any }];
    expect(verifyMerkleProof(proof.leafHash, invalidProofSteps, tree.root)).toBe(false);
  });

  it('Issue #13: verifyApprovalEnvelope enforces separation of duties with 0x prefix', () => {
    const approver = genKeys();
    const approverHex = approver.pub.toString('hex');

    const envelope = {
      incidentId: Buffer.alloc(16, 1),
      protectedScope: 'public.users',
      targetVersionId: Buffer.alloc(16, 2),
      proposedChangesHash: Buffer.alloc(32, 3),
      requesterId: `0x${approverHex}`, // 0x prefixed
      approverPubkey: approver.pub,
      nonce: Buffer.alloc(16, 4),
      expiresAtUs: 9999999999999n,
      signature: Buffer.alloc(64, 0),
    };
    envelope.signature = crypto.sign(null, encodeApprovalPayload(envelope), approver.priv);

    expect(() =>
      verifyApprovalEnvelope(envelope, [approverHex], 1000n)
    ).toThrowError(expect.objectContaining({ code: WolverineErrorCode.REQUESTER_IS_APPROVER }));
  });

  it('Issue #12: computeAttestationDigest differentiates validatorSetId', () => {
    const digest = Buffer.alloc(32, 0xaa);
    const timeUs = 1000000n;
    const digest1 = computeAttestationDigest('c1', 'val1', digest, timeUs, 'valset-v1');
    const digest2 = computeAttestationDigest('c1', 'val1', digest, timeUs, 'valset-v2');
    expect(digest1.equals(digest2)).toBe(false);
  });

  it('Issue #10: OfflineTrustProofVerifier rejects duplicate attestations from single validator', async () => {
    const service = new WolverineTrustNetworkService(3, 5);
    const customer = genKeys();
    service.registerTenant('tenant-1', customer.pub, 'db-1');

    const agent = new WolverineEvidenceAgent({
      tenantId: 'tenant-1',
      databaseId: 'db-1',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      service,
    });

    const cp = {
      checkpointId: '00000000-0000-0000-0000-000000000001',
      commitSeq: 1n,
      scope: 'public.users',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 1),
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs: 1000n,
      protocolVersion: 3,
    };

    const res = await agent.commitCheckpoint(cp, Buffer.alloc(32, 1));
    const proof = JSON.parse(JSON.stringify(res.proof!));

    // Duplicate single attestation to reach quorum count
    const singleAtt = proof.validatorAttestations[0];
    proof.validatorAttestations = [singleAtt, singleAtt, singleAtt, singleAtt, singleAtt];
    // Recompute proof digest for updated attestations
    const { computePortableProofDigest } = await import('../../src/trust_network/proof.js');
    proof.proofDigestHex = computePortableProofDigest(proof).toString('hex');

    const verifyRes = OfflineTrustProofVerifier.verifyPortableProof(proof);
    expect(verifyRes.isValid).toBe(false);
    expect(verifyRes.status).toBe('INVALID_QUORUM');
  });

  it('Issue #11: OfflineTrustProofVerifier validates against external trustedValidatorKeys', async () => {
    const service = new WolverineTrustNetworkService(3, 5);
    const customer = genKeys();
    service.registerTenant('tenant-1', customer.pub, 'db-1');

    const agent = new WolverineEvidenceAgent({
      tenantId: 'tenant-1',
      databaseId: 'db-1',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      service,
    });

    const cp = {
      checkpointId: '00000000-0000-0000-0000-000000000001',
      commitSeq: 1n,
      scope: 'public.users',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 1),
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs: 1000n,
      protocolVersion: 3,
    };

    const res = await agent.commitCheckpoint(cp, Buffer.alloc(32, 1));
    const trustedKeys = new Map<string, Buffer>();
    for (const v of res.proof!.validatorSet) {
      trustedKeys.set(v.validatorId, genKeys().pub); // Mismatched trusted keys
    }

    const verifyRes = OfflineTrustProofVerifier.verifyPortableProof(res.proof!, trustedKeys);
    expect(verifyRes.isValid).toBe(false);
    expect(verifyRes.status).toBe('UNKNOWN_VALIDATOR_SET');
  });

  it('Issue #14: ImmutableTrustReceiptVerifier validates merkleStateRootHex format and mismatch', async () => {
    const service = new WolverineTrustNetworkService(3, 5);
    const customer = genKeys();
    service.registerTenant('tenant-1', customer.pub, 'db-1');

    const agent = new WolverineEvidenceAgent({
      tenantId: 'tenant-1',
      databaseId: 'db-1',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      service,
    });

    const cp = {
      checkpointId: '00000000-0000-0000-0000-000000000001',
      commitSeq: 1n,
      scope: 'public.users',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 1),
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs: 1000n,
      protocolVersion: 3,
    };

    const res = await agent.commitCheckpoint(cp, Buffer.alloc(32, 1));
    const receipt = ImmutableTrustReceiptGenerator.generateReceipt(res.proof!, Buffer.alloc(32, 0x55));

    // Verify with mismatched expected root
    const mismatchRes = ImmutableTrustReceiptVerifier.verifyReceiptOffline(receipt, {
      expectedMerkleRoot: Buffer.alloc(32, 0x99),
    });
    expect(mismatchRes.isValid).toBe(false);
    expect(mismatchRes.status).toContain('MERKLE_STATE_ROOT_MISMATCH');
  });

  it('Issue #16: ReceiptChain breaks and rejects predecessor hash mismatch', async () => {
    const service = new WolverineTrustNetworkService(3, 5);
    const customer = genKeys();
    service.registerTenant('tenant-1', customer.pub, 'db-1');

    const agent = new WolverineEvidenceAgent({
      tenantId: 'tenant-1',
      databaseId: 'db-1',
      customerPubkey: customer.pub,
      customerPrivateKey: customer.priv,
      service,
    });

    const cp1 = {
      checkpointId: '00000000-0000-0000-0000-000000000001',
      commitSeq: 1n,
      scope: 'public.users',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 1),
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs: 1000n,
      protocolVersion: 3,
    };
    const res1 = await agent.commitCheckpoint(cp1, Buffer.alloc(32, 1));
    const r1 = ImmutableTrustReceiptGenerator.generateReceipt(res1.proof!, Buffer.alloc(32, 0x11));

    const cp2 = {
      checkpointId: '00000000-0000-0000-0000-000000000002',
      commitSeq: 2n,
      scope: 'public.users',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 2),
      changeChainHead: Buffer.alloc(32, 1),
      createdAtUs: 2000n,
      protocolVersion: 3,
    };
    const res2 = await agent.commitCheckpoint(cp2, Buffer.alloc(32, 2));
    const r2 = ImmutableTrustReceiptGenerator.generateReceipt(res2.proof!, Buffer.alloc(32, 0x22));

    // Tamper r2's predecessor link
    const tamperedR2 = JSON.parse(JSON.stringify(r2));
    tamperedR2.portableProof.ledgerRecord.previousRecordDigestHex = 'ff'.repeat(32);
    const { computeTrustReceiptDigest } = await import('../../src/trust_receipt/receipt.js');
    tamperedR2.receiptDigestHex = computeTrustReceiptDigest(tamperedR2).toString('hex');

    const chain = new ReceiptChain();
    chain.appendReceipt(r1);
    chain.appendReceipt(tamperedR2);

    expect(chain.verifyChain().isValid).toBe(false);
    expect(chain.findLastVerifiedReceipt()?.receiptId).toBe(r1.receiptId);
  });

  it('Issue #17: FederatedConsensusEngine flags divergence prior to degraded quorum', () => {
    const registry = new NodeRegistry();
    const engine = new FederatedConsensusEngine(registry);
    const expectedRoot = Buffer.alloc(32, 0x11);
    const divergentRoot = Buffer.alloc(32, 0x22);
    const chkId = '00000000-0000-0000-0000-000000000001';

    const keys = [genKeys(), genKeys(), genKeys(), genKeys(), genKeys()];
    for (let i = 0; i < 5; i++) {
      registry.registerNode(`node-${i + 1}`, keys[i]!.pub, ['DATABASE_MUTATION_CAPTURE'], 'org', 'cluster', keys[i]!.priv);
    }

    const policy = {
      totalNodes: 5,
      requiredQuorum: 3,
      nodePublicKeys: new Map(keys.map((k, i) => [`node-${i + 1}`, k.pub])),
    };

    // 1 matching node, 2 divergent nodes -> total 3 nodes responded, below quorum 3 for match
    const attestations = [
      engine.createAttestation('node-1', chkId, expectedRoot, 100n, Buffer.alloc(32), keys[0]!.priv),
      engine.createAttestation('node-2', chkId, divergentRoot, 100n, Buffer.alloc(32), keys[1]!.priv),
      engine.createAttestation('node-3', chkId, divergentRoot, 100n, Buffer.alloc(32), keys[2]!.priv),
    ];

    const result = engine.evaluateConsensus(expectedRoot, attestations, policy);
    expect(result.verdict).toBe('FEDERATION_CONSENSUS_DIVERGENCE');
  });

  it('Issue #18: EpochRotationManager rejects future commitment epochs', () => {
    const ledger = new PersistentTrustLedger();
    const epochManager = new EpochRotationManager(ledger, 2);

    expect(() => epochManager.validateCommitmentEpoch(999)).toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.UNAUTHORIZED_MUTATION })
    );
  });

  it('Issue #19: CustomerKeyRotationManager validates monotonic sequence', async () => {
    const ledger = new PersistentTrustLedger();
    const manager = new CustomerKeyRotationManager(ledger);
    const k1 = genKeys();
    const k2 = genKeys();
    const k3 = genKeys();

    manager.registerInitialKey('t1', k1.pub);
    await manager.executeKeyRotation('t1', 'db1', k1.priv, k1.pub, k2.priv, k2.pub, 5n);

    // Sequence rollback to 4n
    await expect(
      manager.executeKeyRotation('t1', 'db1', k2.priv, k2.pub, k3.priv, k3.pub, 4n)
    ).rejects.toThrowError(expect.objectContaining({ code: WolverineErrorCode.UNAUTHORIZED_MUTATION }));
  });

  it('Issue #20: IncidentCorrelationGraph produces deterministic root digest regardless of insertion order', () => {
    const g1 = new IncidentCorrelationGraph('inc-1');
    g1.addNode('node-B', 'PROCESS', 'Proc B');
    g1.addNode('node-A', 'ACTOR', 'Actor A');
    g1.addEdge('node-B', 'node-A', 'SPAWNED_BY', 1.0);
    g1.addEdge('node-A', 'node-B', 'ACCESSED', 0.8);

    const g2 = new IncidentCorrelationGraph('inc-1');
    g2.addNode('node-A', 'ACTOR', 'Actor A');
    g2.addNode('node-B', 'PROCESS', 'Proc B');
    g2.addEdge('node-A', 'node-B', 'ACCESSED', 0.8);
    g2.addEdge('node-B', 'node-A', 'SPAWNED_BY', 1.0);

    expect(g1.computeGraphRootDigest().equals(g2.computeGraphRootDigest())).toBe(true);
  });

  it('Issue #21: StateDependencyGraphBuilder checks nested object semantic divergence', () => {
    const initialState = new Map();
    const initialRows = new Map();
    initialRows.set('01', {
      tableName: 'public.configs',
      primaryKeyTuple: Buffer.from([1]),
      values: { config: { timeout: 30, retries: 3 } },
      versionId: 'v0',
      commitSeq: 1n,
      deleted: false,
    });
    initialState.set('public.configs', initialRows);

    const builder = new StateDependencyGraphBuilder(initialState);
    const change = {
      formatVersion: 1,
      versionId: 'v1',
      transactionId: 'tx1',
      timestampUs: 1000n,
      tableId: 'public.configs',
      recordId: Buffer.from([1]),
      operation: MutationOperation.UPDATE,
      fieldSet: {
        old: { config: { timeout: 60, retries: 3 } }, // Diverges from timeout: 30
        new: { config: { timeout: 120, retries: 3 } },
      },
      provenance: {},
      previousHash: Buffer.alloc(32, 0),
    };

    const res = builder.analyzeMutationDependency(change, 2n, false);
    expect(res.isConflict).toBe(true);
    expect(res.reason).toContain('Semantic state divergence');
  });

  it('Issue #23: StateDependencyGraphBuilder detects conflict on non-existent row mutation', () => {
    const builder = new StateDependencyGraphBuilder(new Map());
    const change = {
      formatVersion: 1,
      versionId: 'v1',
      transactionId: 'tx1',
      timestampUs: 1000n,
      tableId: 'public.users',
      recordId: Buffer.from([1]),
      operation: MutationOperation.UPDATE,
      fieldSet: {
        old: { name: 'Alice' },
        new: { name: 'Bob' },
      },
      provenance: {},
      previousHash: Buffer.alloc(32, 0),
    };

    const res = builder.analyzeMutationDependency(change, 1n, false);
    expect(res.isConflict).toBe(true);
    expect(res.reason).toContain('Mutation on non-existent row');
  });

  it('Issue #24: VerifiedStateFrontierEngine supports overnight maintenance windows', async () => {
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({ chainId: '1', contractAddress: '0x123', requiredConfirmations: 1 });

    const baseCheckpoint = {
      checkpointId: '00000000-0000-0000-0000-000000000100',
      scope: 'public.orders',
      commitSeq: 100n,
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 1),
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs: 1000n,
      protocolVersion: 1,
    };

    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, baseCheckpoint);
    const digest = computeCheckpointDigest(baseCheckpoint);
    await evmAdapter.anchorCheckpoint(baseCheckpoint.checkpointId, digest, baseCheckpoint.commitSeq);

    const baselineTracker = {
      getBaseline: (actorId: string) => ({
        actorId,
        allowedScopes: ['public.orders'],
        maintenanceWindows: [
          { daysOfWeek: [1, 2, 3, 4, 5], startUtcHour: 22, endUtcHour: 4 }, // 22:00 to 04:00 overnight
        ],
        requiresTicketProvenance: false,
        maxBatchSize: 1000,
        allowedOperations: [MutationOperation.INSERT],
      }),
    };

    const change = {
      formatVersion: 1,
      versionId: '00000000-0000-0000-0000-000000000101',
      transactionId: 'tx1',
      timestampUs: 1000n,
      tableId: 'public.orders',
      recordId: Buffer.from('01', 'hex'),
      operation: MutationOperation.INSERT,
      fieldSet: { new: { id: 1 }, old: null },
      provenance: {},
      previousHash: Buffer.alloc(32, 0),
    };

    const input = {
      baseCheckpoint,
      changesAfterCheckpoint: [
        {
          data: change,
          recordBytes: Buffer.alloc(10),
          computedHash: Buffer.alloc(32, 1),
          commitSeq: 101n,
          actorId: 'batch_worker',
          utcHour: 2, // 02:00 UTC (inside 22..4 overnight window)
          dayOfWeek: 2,
        },
      ],
      baselineTracker: baselineTracker as any,
      externalVaultStore: vaultStore,
      evmAnchorAdapter: evmAdapter,
    };

    const result = await VerifiedStateFrontierEngine.calculateFrontier(input);
    expect(result.isFrontierValid).toBe(true);
    expect(result.preservedChanges.length).toBe(1);
  });

  it('Issue #25: Consistent EMPTY_TREE_ROOT representation', () => {
    const emptyState = new Map();
    const replayRoot = StateReplayEngine.computeStateMerkleRoot(emptyState);
    const ledger = new PersistentTrustLedger();
    const ledgerRoot = ledger.computeMerkleStateRoot();
    const treeRoot = new MerkleTree([]).root;

    expect(replayRoot.equals(EMPTY_TREE_ROOT)).toBe(true);
    expect(ledgerRoot.equals(EMPTY_TREE_ROOT)).toBe(true);
    expect(treeRoot.equals(EMPTY_TREE_ROOT)).toBe(true);
  });

  it('Issue #28: EvmAnchorAdapter preserves ORPHANED_REORG status on block advance', () => {
    const adapter = new EvmAnchorAdapter({ chainId: '1', contractAddress: '0x123', requiredConfirmations: 2 });
    adapter.anchorCheckpoint('chk-1', Buffer.alloc(32, 1), 10n);
    adapter.triggerReorg(5n);

    // Advance block
    adapter.advanceBlock(10n);
    const record = (adapter as any).onChainRegistry.get('chk-1');
    expect(record.status).toBe(AnchorStatus.ORPHANED_REORG);
  });

  it('Issue #31: matchesProtectedScope supports multi-part schema and table names', () => {
    expect(matchesProtectedScope('analytics.mart.users', 'analytics.mart.*')).toBe(true);
    expect(matchesProtectedScope('public.users', 'public')).toBe(true);
    expect(matchesProtectedScope('public.users', 'public.*')).toBe(true);
    expect(matchesProtectedScope('secret.admin', 'public.*')).toBe(false);
  });
});
