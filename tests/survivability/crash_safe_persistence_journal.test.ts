import { describe, it, expect } from 'vitest';
import {
  CrashSafeValidatorJournal,
} from '../../src/index.js';

describe('Crash-Safe Persistence Journal (WDB-0121)', () => {
  it('recovers from truncated tail and fails closed on intermediate corrupted bytes', () => {
    const journal = new CrashSafeValidatorJournal('val-test-01');

    for (let i = 1; i <= 5; i++) {
      journal.append(
        1,
        BigInt(i),
        Buffer.alloc(32, i),
        Buffer.alloc(32, i - 1),
        Buffer.alloc(32, i + 10),
        Buffer.alloc(32, i + 20),
        Buffer.alloc(32, 1)
      );
    }

    const rawRecords = journal.getRecords();
    expect(rawRecords.length).toBe(5);

    // 1. SIMULATE POWER LOSS / TRUNCATED TAIL ON 5TH RECORD
    const truncatedRecords = [...rawRecords];
    // Corrupt only the 5th (last) record
    truncatedRecords[4] = {
      ...truncatedRecords[4]!,
      commitmentDigest: Buffer.alloc(32, 0xee), // Corrupted tail
    };

    const recoveryJournal = new CrashSafeValidatorJournal('val-test-01');
    const recResult = recoveryJournal.recoverFromRaw(truncatedRecords);

    // Recovered up to 4, truncated tail reported
    expect(recResult.recoveredCount).toBe(4);
    expect(recResult.truncatedTail).toBe(true);

    // 2. SIMULATE INTERMEDIATE CORRUPTED RECORD (AT INDEX 2)
    const corruptedIntermediate = [...rawRecords];
    corruptedIntermediate[2] = {
      ...corruptedIntermediate[2]!,
      commitmentDigest: Buffer.alloc(32, 0xff), // Corrupted intermediate
    };

    const corruptedJournal = new CrashSafeValidatorJournal('val-test-01');
    expect(() => corruptedJournal.recoverFromRaw(corruptedIntermediate)).toThrow(/Corrupted journal record/);
  });
});
