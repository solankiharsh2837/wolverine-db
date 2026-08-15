import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  PersistentTrustLedger,
  EpochRotationManager,
  CustomerKeyRotationManager,
  createSignedCustomerCommitment,
  verifyCustomerCommitment,
} from '../../src/index.js';

describe('Dynamic Epoch and Customer Key Rotation (WDB-0111, WDB-0113)', () => {
  const genKeys = () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pub = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { pub, priv: pair.privateKey };
  };

  it('rotations: advances epoch and performs dual-signed key rotation', async () => {
    const ledger = new PersistentTrustLedger();
    const epochManager = new EpochRotationManager(ledger, 1);
    const keyManager = new CustomerKeyRotationManager(ledger);

    const oldKeys = genKeys();
    const newKeys = genKeys();

    keyManager.registerInitialKey('tenant-rotation-corp', oldKeys.pub);

    // 1. Advance network epoch from 1 to 2
    const transition = await epochManager.advanceEpoch('valset-prod-v2');
    expect(transition.newEpoch).toBe(2);
    expect(epochManager.getCurrentEpoch()).toBe(2);

    // 2. Execute dual-signed key rotation
    const rotationRecord = await keyManager.executeKeyRotation(
      'tenant-rotation-corp',
      'orders-db',
      oldKeys.priv,
      oldKeys.pub,
      newKeys.priv,
      newKeys.pub,
      1n
    );

    expect(rotationRecord.oldPubkeyHex).toBe(oldKeys.pub.toString('hex'));
    expect(rotationRecord.newPubkeyHex).toBe(newKeys.pub.toString('hex'));
    expect(keyManager.getActiveKey('tenant-rotation-corp')?.toString('hex')).toBe(
      newKeys.pub.toString('hex')
    );

    // 3. New commitments signed by new key are valid
    const newCommitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'tenant-rotation-corp',
        databaseId: 'orders-db',
        checkpointId: '00000000-0000-0000-0000-000000002001',
        commitSeq: 2001n,
        checkpointDigest: Buffer.alloc(32, 0x55),
        previousTrustCommitment: Buffer.alloc(32, 0),
        epoch: 2,
      },
      newKeys.priv,
      newKeys.pub
    );

    const isValid = verifyCustomerCommitment(newCommitment, newKeys.pub);
    expect(isValid).toBe(true);

    // Old key fails
    const isOldValid = verifyCustomerCommitment(newCommitment, oldKeys.pub);
    expect(isOldValid).toBe(false);
  });
});
