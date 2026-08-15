import { describe, it, expect } from 'vitest';
import {
  EpochTransitionCertificateManager,
} from '../../src/index.js';

describe('Epoch Transition Certificate Protocol (WDB-0124)', () => {
  it('creates and validates dual-quorum epoch transition certificates and rejects insufficient quorums', () => {
    const oldSigs = [
      { validatorId: 'val-01', signature: Buffer.alloc(64, 1) },
      { validatorId: 'val-02', signature: Buffer.alloc(64, 2) },
      { validatorId: 'val-03', signature: Buffer.alloc(64, 3) },
      { validatorId: 'val-04', signature: Buffer.alloc(64, 4) },
    ];

    const newSigs = [
      { validatorId: 'val-01', signature: Buffer.alloc(64, 1) },
      { validatorId: 'val-02', signature: Buffer.alloc(64, 2) },
      { validatorId: 'val-03', signature: Buffer.alloc(64, 3) },
      { validatorId: 'val-05', signature: Buffer.alloc(64, 5) },
    ];

    const cert = EpochTransitionCertificateManager.createCertificate(
      1,
      2,
      Buffer.alloc(32, 0xaa),
      Buffer.alloc(32, 0xbb),
      100n,
      'SCHEDULED_ROTATION',
      oldSigs,
      newSigs
    );

    expect(cert.oldEpoch).toBe(1);
    expect(cert.newEpoch).toBe(2);
    expect(EpochTransitionCertificateManager.verifyCertificate(cert, 4)).toBe(true);

    // Insufficient old quorum (3 of 4)
    const badCert = EpochTransitionCertificateManager.createCertificate(
      1,
      2,
      Buffer.alloc(32, 0xaa),
      Buffer.alloc(32, 0xbb),
      100n,
      'SCHEDULED_ROTATION',
      oldSigs.slice(0, 3), // Only 3 signatures!
      newSigs
    );

    expect(() => EpochTransitionCertificateManager.verifyCertificate(badCert, 4)).toThrow(
      /Old quorum signatures insufficient/
    );
  });
});
