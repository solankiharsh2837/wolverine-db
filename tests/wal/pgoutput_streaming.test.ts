import { describe, it, expect } from 'vitest';
import { PgOutputDecoder } from '../../src/wal/pgoutput_decoder.js';

describe('PgOutputDecoder PostgreSQL 14+ Streaming Replication Messages', () => {
  const decoder = new PgOutputDecoder();

  it('decodes Stream Start (S) message', () => {
    const buf = Buffer.alloc(6);
    buf.writeUInt8('S'.charCodeAt(0), 0);
    buf.writeUInt32BE(4096, 1);
    buf.writeUInt8(1, 5); // first segment = 1

    const msg = decoder.decodeMessage(buf);
    expect(msg.type).toBe('S');
    if (msg.type === 'S') {
      expect(msg.xid).toBe('4096');
      expect(msg.firstSegment).toBe(1);
    }
  });

  it('decodes Stream Stop (E) message', () => {
    const buf = Buffer.alloc(1);
    buf.writeUInt8('E'.charCodeAt(0), 0);

    const msg = decoder.decodeMessage(buf);
    expect(msg.type).toBe('E');
  });

  it('decodes Stream Commit (c) message', () => {
    const buf = Buffer.alloc(30);
    buf.writeUInt8('c'.charCodeAt(0), 0);
    buf.writeUInt32BE(4096, 1);
    buf.writeUInt8(0, 5); // flags
    buf.writeBigUInt64BE(0x1800000n, 6); // commit LSN
    buf.writeBigUInt64BE(0x1800100n, 14); // end LSN
    buf.writeBigInt64BE(1700000000000000n, 22); // commit time

    const msg = decoder.decodeMessage(buf);
    expect(msg.type).toBe('c');
    if (msg.type === 'c') {
      expect(msg.xid).toBe('4096');
      expect(msg.commitLsn).toBe('0/1800000');
    }
  });

  it('decodes Stream Abort (A) message', () => {
    const buf = Buffer.alloc(9);
    buf.writeUInt8('A'.charCodeAt(0), 0);
    buf.writeUInt32BE(4096, 1);
    buf.writeUInt32BE(4097, 5);

    const msg = decoder.decodeMessage(buf);
    expect(msg.type).toBe('A');
    if (msg.type === 'A') {
      expect(msg.xid).toBe('4096');
      expect(msg.subxid).toBe('4097');
    }
  });
});
