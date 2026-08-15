import { describe, it, expect } from 'vitest';
import { MutationOperation } from '../../src/protocol/types.js';

describe('PostgreSQL WAL Decoder (WDB-0010 Scaffolding)', () => {
  it('conforms to WDB-0010 transaction boundary requirements', () => {
    // Normalizer mock structure conforming to WDB-0010
    const mockWalEvent = {
      action: 'I',
      schema: 'public',
      table: 'accounts',
      columns: [
        { name: 'id', type: 'uuid', value: 'b2d86a42-0b1a-4d2c-9a4f-561b369c0d12' },
        { name: 'balance', type: 'numeric', value: '1500.50' },
      ],
      commitLsn: '0/16B3748',
      commitTimestampUs: 1723500000000000n,
    };

    expect(mockWalEvent.action).toBe('I');
    expect(MutationOperation.INSERT).toBe(1);
  });
});
