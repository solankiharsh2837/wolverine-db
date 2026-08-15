import { describe, it, expect } from 'vitest';
import { WalDecoder } from '../../src/wal/decoder.js';
import { WalReceiver } from '../../src/wal/receiver.js';
import { GENESIS_PREDECEASED_HASH } from '../../src/crypto/hash.js';
import { WolverineError } from '../../src/errors/index.js';

describe('WAL Capture Properties (WDB-0010 Hardening)', () => {
  it('property: captures committed transactions and ignores rolled-back transactions', () => {
    const receiver = new WalReceiver({
      slotName: 'wdb_test_slot',
      protectedTables: ['public.accounts'],
    });

    receiver.start();

    // Stream 1: Committed transaction
    const committedStream = `
BEGIN 101
table public.accounts: INSERT: id[uuid]:'11111111-1111-1111-1111-111111111111' balance[numeric]:'500.00'
COMMIT 101
    `.trim();

    const changes1 = receiver.ingestStreamData(committedStream, GENESIS_PREDECEASED_HASH);
    expect(changes1).toHaveLength(1);
    expect(changes1[0].changeRecordData.transactionId).toBe('tx:101');

    // Stream 2: Rolled-back / aborted transaction
    const rolledBackStream = `
BEGIN 102
table public.accounts: INSERT: id[uuid]:'22222222-2222-2222-2222-222222222222' balance[numeric]:'999.00'
ABORT 102
    `.trim();

    const changes2 = receiver.ingestStreamData(rolledBackStream, changes1[0].changeHash);
    expect(changes2).toHaveLength(0); // Zero changes emitted for abort
  });

  it('property: enforces LSN monotonicity and acknowledgment safety', () => {
    const receiver = new WalReceiver({
      slotName: 'wdb_slot',
      protectedTables: ['public.accounts'],
      startLsn: '0/1000',
    });

    receiver.start();
    expect(receiver.confirmedLsn).toBe('0/1000');

    const stream = `
BEGIN 201
table public.accounts: UPDATE: id[uuid]:'11111111-1111-1111-1111-111111111111' balance[numeric]:'750.00'
COMMIT 201
    `.trim();

    receiver.ingestStreamData(stream, GENESIS_PREDECEASED_HASH);
    const ack = receiver.acknowledgeLsn('0/2000');
    expect(ack.confirmedFlushLsn).toBe('0/2000');
    expect(receiver.confirmedLsn).toBe('0/2000');
  });

  it('property: deduplicates replayed WAL transactions on reconnect / restart', () => {
    const receiver = new WalReceiver({
      slotName: 'wdb_slot',
      protectedTables: ['public.accounts'],
    });

    receiver.start();

    const stream = `
BEGIN 301
table public.accounts: INSERT: id[uuid]:'33333333-3333-3333-3333-333333333333' balance[numeric]:'100.00'
COMMIT 301
    `.trim();

    const firstRun = receiver.ingestStreamData(stream, GENESIS_PREDECEASED_HASH);
    expect(firstRun).toHaveLength(1);

    // Replay exact same transaction (simulating crash recovery before LSN flush)
    const replayRun = receiver.ingestStreamData(stream, GENESIS_PREDECEASED_HASH);
    expect(replayRun).toHaveLength(0); // Deduplicated
  });

  it('property: rejects malformed WAL messages and recovers from decoder errors', () => {
    const decoder = new WalDecoder();

    // Commit without Begin throws malformed record error
    expect(() => {
      decoder.processLine('COMMIT 999');
    }).toThrow(WolverineError);

    // Decoder recovers cleanly after reset
    decoder.reset();
    decoder.processLine('BEGIN 1000');
    decoder.processLine("table public.accounts: INSERT: id[uuid]:'44444444-4444-4444-4444-444444444444' balance[numeric]:'200.00'");
    const block = decoder.processLine('COMMIT 1000');
    expect(block).not.toBeNull();
    expect(block?.mutations).toHaveLength(1);
  });

  it('property: safely handles replication slot pause and resumption', async () => {
    const receiver = new WalReceiver({
      slotName: 'wdb_slot',
      protectedTables: ['public.accounts'],
    });

    await receiver.start();
    expect(receiver.isRunning).toBe(true);

    await receiver.stop();
    expect(receiver.isRunning).toBe(false);

    expect(() => {
      receiver.ingestStreamData('BEGIN 10\nCOMMIT 10', GENESIS_PREDECEASED_HASH);
    }).toThrow('Cannot ingest WAL data while receiver is stopped');
  });
});
