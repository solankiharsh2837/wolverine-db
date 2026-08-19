import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  ValidatorSetManager,
  CryptographicAdmissionGate,
  BootAdmissionState,
} from '../src/index.js';

describe('Milestone 6.5 — Cryptographic Admission Gate & Supply-Chain Defense', () => {
  const kp1 = crypto.generateKeyPairSync('ed25519');
  const kp2 = crypto.generateKeyPairSync('ed25519');
  const rogueKp = crypto.generateKeyPairSync('ed25519');

  const valSetManager = new ValidatorSetManager({
    validatorSetId: 'valset-admission-01',
    epoch: 1,
    quorumThreshold: 2,
    totalValidators: 2,
    validators: [
      {
        validatorId: 'val-01',
        publicKeyHex: kp1.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
        weight: 1,
      },
      {
        validatorId: 'val-02',
        publicKeyHex: kp2.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
        weight: 1,
      },
    ],
  });

  it('1. Valid Node Admission: grants READY state when all cryptographic checks pass', () => {
    const result = CryptographicAdmissionGate.evaluateAdmission({
      validatorId: 'val-01',
      protocolVersion: 2,
      epoch: 1,
      privateKey: kp1.privateKey,
      validatorSetManager: valSetManager,
    });

    expect(result.admitted).toBe(true);
    expect(result.state).toBe(BootAdmissionState.READY);
  });

  it('2. Unknown Validator Identity: rejected and quarantined', () => {
    const result = CryptographicAdmissionGate.evaluateAdmission({
      validatorId: 'val-unknown-99',
      protocolVersion: 2,
      epoch: 1,
      privateKey: kp1.privateKey,
      validatorSetManager: valSetManager,
    });

    expect(result.admitted).toBe(false);
    expect(result.state).toBe(BootAdmissionState.QUARANTINED);
    expect(result.reason).toContain('Unknown validator identity');
  });

  it('3. Protocol Version Incompatibility: rejected and quarantined', () => {
    const result = CryptographicAdmissionGate.evaluateAdmission({
      validatorId: 'val-01',
      protocolVersion: 1, // Outdated v1 protocol
      epoch: 1,
      privateKey: kp1.privateKey,
      validatorSetManager: valSetManager,
    });

    expect(result.admitted).toBe(false);
    expect(result.state).toBe(BootAdmissionState.QUARANTINED);
    expect(result.reason).toContain('Incompatible protocol version');
  });

  it('4. Stolen/Forged Private Key Mismatch: rejected and quarantined', () => {
    const result = CryptographicAdmissionGate.evaluateAdmission({
      validatorId: 'val-01',
      protocolVersion: 2,
      epoch: 1,
      privateKey: rogueKp.privateKey, // Wrong key!
      validatorSetManager: valSetManager,
    });

    expect(result.admitted).toBe(false);
    expect(result.state).toBe(BootAdmissionState.QUARANTINED);
    expect(result.reason).toContain('Private key does not correspond to registered public key');
  });

  it('5. Unresolved Quarantined Disasters: rejected at boot', () => {
    const result = CryptographicAdmissionGate.evaluateAdmission({
      validatorId: 'val-01',
      protocolVersion: 2,
      epoch: 1,
      privateKey: kp1.privateKey,
      validatorSetManager: valSetManager,
      hasUnresolvedDisasters: true,
    });

    expect(result.admitted).toBe(false);
    expect(result.state).toBe(BootAdmissionState.QUARANTINED);
    expect(result.reason).toContain('unresolved quarantined disasters');
  });
});
