import { describe, it, expect } from 'vitest';
import { CrossDomainVerifier } from '../../src/anchors/verifier.js';
import { WORMCheckpointStore } from '../../src/checkpoint/worm.js';
import { EvmAnchorAdapter } from '../../src/anchors/evm.js';
import { computeCheckpointDigest, CheckpointAnchorEngine } from '../../src/checkpoint/anchor.js';

describe('Cross-Domain Verification (WDB-0022 Hardening)', () => {
  const checkpointId = '00000000-0000-0000-0000-000000000050';
  const scope = 'public.ledger';
  const commitSeq = 50n;
  const createdAtUs = 1723500000000000n;
  const honestRoot = Buffer.alloc(32, 0x50);

  it('property: 100% agreement across Database, Vault, and Blockchain -> AUTHENTIC', async () => {
    const vaultStore = new WORMCheckpointStore();
    const evmAdapter = new EvmAnchorAdapter({
      chainId: '1',
      contractAddress: '0x1234567890123456789012345678901234567890',
      requiredConfirmations: 1,
    });

    // Anchor to external vault
    await CheckpointAnchorEngine.anchorCheckpoint(vaultStore, {
      checkpointId,
      scope,
      commitSeq,
      previousCheckpointId: null,
      merkleRoot: honestRoot,
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs,
      protocolVersion: 3,
    });

    // Compute canonical digest and anchor to EVM blockchain
    const honestDigest = computeCheckpointDigest({
      checkpointId,
      scope,
      commitSeq,
      previousCheckpointId: null,
      merkleRoot: honestRoot,
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs,
      protocolVersion: 3,
    });
    await evmAdapter.anchorCheckpoint(checkpointId, honestDigest, commitSeq);

    const report = await CrossDomainVerifier.verifyCrossDomain(
      checkpointId,
      honestRoot,
      commitSeq,
      scope,
      createdAtUs,
      vaultStore,
      [evmAdapter]
    );

    expect(report.status).toBe('AUTHENTIC');
  });

  it('property: detects local database tampering when Vault and Blockchain agree', async () => {
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
      merkleRoot: honestRoot,
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs,
      protocolVersion: 3,
    });

    const honestDigest = computeCheckpointDigest({
      checkpointId,
      scope,
      commitSeq,
      previousCheckpointId: null,
      merkleRoot: honestRoot,
      changeChainHead: Buffer.alloc(32, 0),
      createdAtUs,
      protocolVersion: 3,
    });
    await evmAdapter.anchorCheckpoint(checkpointId, honestDigest, commitSeq);

    // Attacker modifies live DB root
    const tamperedLocalRoot = Buffer.alloc(32, 0xde);

    const report = await CrossDomainVerifier.verifyCrossDomain(
      checkpointId,
      tamperedLocalRoot,
      commitSeq,
      scope,
      createdAtUs,
      vaultStore,
      [evmAdapter]
    );

    expect(report.status).toBe('LOCAL_TAMPERING_DETECTED');
    expect(report.details).toContain('Local state divergence detected');
  });
});
