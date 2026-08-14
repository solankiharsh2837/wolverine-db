import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { canonicalizeJson } from '../src/binary/c14n.js';
import { encodePrimaryKeyTuple } from '../src/binary/record_id.js';
import { encodeBinaryRecord } from '../src/binary/encoder.js';
import { computeChangeHash, sha256 } from '../src/crypto/hash.js';
import { computeMerkleLeafHash, computeMerkleNodeHash, EMPTY_TREE_ROOT } from '../src/crypto/merkle.js';
import { encodeApprovalPayload } from '../src/crypto/approval.js';

describe('Normative Test Vectors (specs/TEST-VECTORS.md)', () => {
  it('1. Domain-Separated Constants & Empty Merkle Root', () => {
    expect(EMPTY_TREE_ROOT.toString('hex')).toBe(
      '8e4f2728690f5b33a7e61d15881334c705770f18450ecdc1c3b77f02f3df6024'
    );
  });

  it('2. Merkle Leaf Hash Formula', () => {
    const leafPayload = Buffer.from('test_leaf_payload', 'ascii');
    const leafHash = computeMerkleLeafHash(leafPayload);
    expect(leafHash.toString('hex')).toBe(
      '1e6ebc3db5f2c97294b84401ed2722cc84ddd3ae5b946ede528edda2ffc9674b'
    );
  });

  it('2. Merkle Internal Node Hash Formula', () => {
    const leftHash = Buffer.alloc(32, 1);
    const rightHash = Buffer.alloc(32, 2);
    const nodeHash = computeMerkleNodeHash(leftHash, rightHash);
    expect(nodeHash.toString('hex')).toBe(
      'bca27582de55580e19701dd8a76955d3162a7f4c8f927a7f0d4910d02d8660bc'
    );
  });

  it('3. RFC 8785 Canonical JSON (JSON-C14N)', () => {
    const jsonObj = { b: 1, a: 2, '10': 3 };
    const c14nStr = canonicalizeJson(jsonObj);
    expect(c14nStr).toBe('{"10":3,"a":2,"b":1}');
    expect(Buffer.from(c14nStr, 'utf8').toString('hex')).toBe(
      '7b223130223a332c2261223a322c2262223a317d'
    );
  });

  it('4. Canonical Primary Key Tuple (RECORD_ID)', () => {
    const valBuf = Buffer.alloc(8);
    valBuf.writeBigUInt64BE(42n, 0);

    const tupleBuf = encodePrimaryKeyTuple([
      { name: 'id', typeTag: 2, valueBuffer: valBuf },
    ]);

    expect(tupleBuf.toString('hex')).toBe(
      '0001000269640200000008000000000000002a'
    );
  });

  it('5. Canonical CHANGE Record Binary Envelope & Hash', () => {
    const valBuf = Buffer.alloc(8);
    valBuf.writeBigUInt64BE(42n, 0);
    const pkTuple = encodePrimaryKeyTuple([
      { name: 'id', typeTag: 2, valueBuffer: valBuf },
    ]);

    const formatVerBuf = Buffer.from('0000000000000001', 'hex');
    const versionIdBuf = Buffer.alloc(16, 0);
    const txIdBuf = Buffer.from('tx:1001', 'utf8');
    const timestampBuf = Buffer.alloc(8, 0);
    const tableIdBuf = Buffer.from('public.users', 'utf8');
    const opBuf = Buffer.from('0000000000000001', 'hex');
    const fieldSetBuf = Buffer.from('{"new":{"name":"Alice"},"old":null}', 'utf8');
    const provenanceBuf = Buffer.from('{"actor":"user1"}', 'utf8');
    const prevHashBuf = Buffer.alloc(32, 0);

    const recordBytes = encodeBinaryRecord(1, [
      { tag: 1, typeTag: 2, payload: formatVerBuf },
      { tag: 2, typeTag: 4, payload: versionIdBuf },
      { tag: 3, typeTag: 5, payload: txIdBuf },
      { tag: 4, typeTag: 10, payload: timestampBuf },
      { tag: 5, typeTag: 5, payload: tableIdBuf },
      { tag: 6, typeTag: 6, payload: pkTuple },
      { tag: 7, typeTag: 2, payload: opBuf },
      { tag: 8, typeTag: 8, payload: fieldSetBuf },
      { tag: 9, typeTag: 8, payload: provenanceBuf },
      { tag: 10, typeTag: 7, payload: prevHashBuf },
    ]);

    expect(recordBytes.length).toBe(241);
    expect(recordBytes.toString('hex')).toBe(
      '57444201010000000a00010200000008000000000000000100020400000010000000000000000000000000000000000003050000000774783a3130303100040a0000000800000000000000000005050000000c7075626c69632e7573657273000606000000130001000269640200000008000000000000002a000702000000080000000000000001000808000000237b226e6577223a7b226e616d65223a22416c696365227d2c226f6c64223a6e756c6c7d000908000000117b226163746f72223a227573657231227d000a07000000200000000000000000000000000000000000000000000000000000000000000000'
    );

    const changeHash = computeChangeHash(recordBytes, prevHashBuf);
    expect(changeHash.toString('hex')).toBe(
      '71ae3610dd6022516bae0156f220baa1a0e5408b76aba8f98ffe44a89fa6e9f3'
    );
  });

  it('6. Ed25519 Policy Approval Payload Format', () => {
    const payload = encodeApprovalPayload({
      incidentId: Buffer.alloc(16, 1),
      protectedScope: 'public.users',
      targetVersionId: Buffer.alloc(16, 2),
      proposedChangesHash: Buffer.alloc(32, 3),
      requesterId: 'admin@example.com',
      approverPubkey: Buffer.from(
        'c225c99bf94417cc2f4b50d5e7f1b0e4f7ad1e185316244fd6ca0ae13aa65db7',
        'hex'
      ),
      nonce: Buffer.alloc(16, 4),
      expiresAtUs: 1800000000000000n,
    });

    expect(payload.toString('hex')).toBe(
      '010101010101010101010101010101017075626c69632e757365727302020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030361646d696e406578616d706c652e636f6dc225c99bf94417cc2f4b50d5e7f1b0e4f7ad1e185316244fd6ca0ae13aa65db7040404040404040404040404040404040006651728988000'
    );
  });
});
