import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  WolverineProductionCluster,
  createSignedCustomerCommitment,
  ImmutableTrustReceiptGenerator,
  ValidatorStateProofEngine,
  ValidatorStateProof,
  MaliciousSnapshotDefense,
  computeSnapshotDigest,
  LedgerSnapshot,
} from '../../src/index.js';

describe('Byzantine State Proof & Malicious Snapshot Defense (WDB-0125)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('selects state based on cryptographic finality instead of numerical majority', async () => {
    const cluster = new WolverineProductionCluster({ totalValidators: 5, requiredQuorum: 4 });
    const customer = genKeys();
    cluster.registerTenant('tenant-bft-proof', customer.pub, 'db-proof');

    const cmt = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'tenant-bft-proof',
        databaseId: 'db-proof',
        checkpointId: '00000000-0000-0000-0000-000000000500',
        commitSeq: 500n,
        checkpointDigest: Buffer.alloc(32, 0x50),
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      customer.priv,
      customer.pub
    );

    const { proof } = await cluster.submitCommitment(cmt);
    const receipt = ImmutableTrustReceiptGenerator.generateReceipt(
      proof,
      cluster.ledger.getMerkleStateRoot()
    );

    const authenticProof: ValidatorStateProof = {
      validatorId: 'val-01',
      ledgerSeq: 500n,
      ledgerStateRootHex: cluster.ledger.getMerkleStateRoot().toString('hex'),
      journalHeadDigestHex: cluster.ledger.getStateRootSnapshot().chainHeadDigest.toString('hex'),
      epoch: 1,
      validatorSetDigestHex: Buffer.alloc(32, 1).toString('hex'),
      latestReceipt: receipt,
    };

    // 3 Dishonest/Lying validators claim a higher seq (999) WITHOUT a valid receipt
    const fakeProof1: ValidatorStateProof = {
      validatorId: 'val-02',
      ledgerSeq: 999n,
      ledgerStateRootHex: Buffer.alloc(32, 0xfe).toString('hex'),
      journalHeadDigestHex: Buffer.alloc(32, 0xfe).toString('hex'),
      epoch: 1,
      validatorSetDigestHex: Buffer.alloc(32, 1).toString('hex'),
      latestReceipt: undefined, // No receipt!
    };
    const fakeProof2: ValidatorStateProof = { ...fakeProof1, validatorId: 'val-03' };
    const fakeProof3: ValidatorStateProof = { ...fakeProof1, validatorId: 'val-04' };

    const chosen = ValidatorStateProofEngine.selectAuthoritativeState([
      fakeProof1,
      fakeProof2,
      fakeProof3,
      authenticProof,
    ]);

    expect(chosen.validatorId).toBe('val-01');
    expect(chosen.ledgerSeq).toBe(500n);
  });

  it('detects forged snapshot from compromised storage and falls back to clean state', async () => {
    const cluster = new WolverineProductionCluster({ totalValidators: 5, requiredQuorum: 4 });
    const records = cluster.ledger.getRecords();

    const cleanSnapshotBase = {
      snapshotId: 'snap-clean',
      epoch: 1,
      snapshotLedgerSeq: 0n,
      stateRoot: Buffer.alloc(32, 0),
      chainHeadDigest: Buffer.alloc(32, 0),
      validatorSetDigest: Buffer.alloc(32, 1),
      timestampUs: 1723500000000000n,
      records: [],
    };
    const cleanSnapshot: LedgerSnapshot = {
      ...cleanSnapshotBase,
      snapshotDigest: computeSnapshotDigest(cleanSnapshotBase),
    };

    // Forged candidate snapshot with tampered internal bytes
    const forgedSnapshot: LedgerSnapshot = {
      ...cleanSnapshotBase,
      snapshotId: 'snap-forged',
      stateRoot: Buffer.alloc(32, 0xcc),
      snapshotDigest: Buffer.alloc(32, 0xee), // Invalid digest
    };

    const defenseRes = MaliciousSnapshotDefense.detectAndRecover(
      forgedSnapshot,
      cleanSnapshot,
      records
    );

    expect(defenseRes.isForgedSnapshotDetected).toBe(true);
    expect(defenseRes.recoveryResult.isSuccess).toBe(true);
  });
});
