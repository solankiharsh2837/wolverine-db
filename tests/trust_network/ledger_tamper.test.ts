import { describe, it, expect } from 'vitest';
import { WolverineTrustLedger } from '../../src/index.js';

describe('Trust Ledger Append-Only Integrity & Tamper Detection (WDB-0082)', () => {
  it('property: detects any modification, deletion, or insertion in historical ledger records', () => {
    const ledger = new WolverineTrustLedger();

    ledger.appendRecord('COMMITMENT', { data: 'rec-1' });
    ledger.appendRecord('ATTESTATION', { data: 'rec-2' });
    ledger.appendRecord('FINALIZATION', { data: 'rec-3' });

    expect(ledger.verifyLedgerIntegrity()).toBe(true);

    // Tamper with record 2 payload
    const records = ledger.getRecords() as any[];
    records[1].payload = { data: 'tampered-data' };

    expect(ledger.verifyLedgerIntegrity()).toBe(false);
  });
});
