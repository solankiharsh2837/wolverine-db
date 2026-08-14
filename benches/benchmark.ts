import crypto from 'node:crypto';
import { encodeBinaryRecord } from '../src/binary/encoder.js';
import { decodeBinaryRecord } from '../src/binary/decoder.js';
import { computeChangeHash, GENESIS_PREDECEASED_HASH } from '../src/crypto/hash.js';
import { MerkleTree } from '../src/crypto/merkle.js';
import { encodeApprovalPayload, verifyApprovalEnvelope } from '../src/crypto/approval.js';

function formatDurationMs(startNs: bigint): string {
  const diffNs = process.hrtime.bigint() - startNs;
  return (Number(diffNs) / 1e6).toFixed(3) + ' ms';
}

function runBenchmark() {
  console.log('====================================================');
  console.log('  WolverineDB v0.1.0-rc1 Performance Benchmarks');
  console.log('====================================================\n');

  // 1. Binary Encoding Benchmark
  const valBuf = Buffer.alloc(8); valBuf.writeBigUInt64BE(42n);
  const pkTuple = Buffer.concat([Buffer.from('0001000269640200000008', 'hex'), valBuf]);

  const testFields = [
    { tag: 1, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
    { tag: 2, typeTag: 4, payload: Buffer.alloc(16, 0) },
    { tag: 3, typeTag: 5, payload: Buffer.from('tx:1001', 'utf8') },
    { tag: 4, typeTag: 10, payload: Buffer.alloc(8, 0) },
    { tag: 5, typeTag: 5, payload: Buffer.from('public.users', 'utf8') },
    { tag: 6, typeTag: 6, payload: pkTuple },
    { tag: 7, typeTag: 2, payload: Buffer.from('0000000000000001', 'hex') },
    { tag: 8, typeTag: 8, payload: Buffer.from('{"new":{"name":"Alice"},"old":null}', 'utf8') },
    { tag: 9, typeTag: 8, payload: Buffer.from('{"actor":"user1"}', 'utf8') },
    { tag: 10, typeTag: 7, payload: GENESIS_PREDECEASED_HASH },
  ];

  const N_ENCODE = 10_000;
  const startEncode = process.hrtime.bigint();
  let sampleBytes!: Buffer;
  for (let i = 0; i < N_ENCODE; i++) {
    sampleBytes = encodeBinaryRecord(1, testFields);
  }
  const encodeTime = formatDurationMs(startEncode);
  const encodeThroughput = Math.round((N_ENCODE / (Number(process.hrtime.bigint() - startEncode) / 1e9)));
  console.log(`[1] Binary Record Encoding (${N_ENCODE.toLocaleString()} ops):`);
  console.log(`    Total Time: ${encodeTime}`);
  console.log(`    Throughput: ${encodeThroughput.toLocaleString()} records/sec`);
  console.log(`    Record Size: ${sampleBytes.length} bytes`);

  // 2. Binary Decoding Benchmark
  const startDecode = process.hrtime.bigint();
  for (let i = 0; i < N_ENCODE; i++) {
    decodeBinaryRecord(sampleBytes);
  }
  const decodeTime = formatDurationMs(startDecode);
  const decodeThroughput = Math.round((N_ENCODE / (Number(process.hrtime.bigint() - startDecode) / 1e9)));
  console.log(`\n[2] Binary Record Decoding (${N_ENCODE.toLocaleString()} ops):`);
  console.log(`    Total Time: ${decodeTime}`);
  console.log(`    Throughput: ${decodeThroughput.toLocaleString()} records/sec`);

  // 3. Change Hash Chain Computation Benchmark
  const startHash = process.hrtime.bigint();
  let prevHash = GENESIS_PREDECEASED_HASH;
  for (let i = 0; i < N_ENCODE; i++) {
    prevHash = computeChangeHash(sampleBytes, prevHash);
  }
  const hashTime = formatDurationMs(startHash);
  const hashThroughput = Math.round((N_ENCODE / (Number(process.hrtime.bigint() - startHash) / 1e9)));
  console.log(`\n[3] SHA-256 Change Hash Chain (${N_ENCODE.toLocaleString()} ops):`);
  console.log(`    Total Time: ${hashTime}`);
  console.log(`    Throughput: ${hashThroughput.toLocaleString()} hashes/sec`);

  // 4. Merkle Tree Benchmark (1,000 / 10,000 / 50,000 leaves)
  for (const count of [1_000, 10_000, 50_000]) {
    const leaves = Array.from({ length: count }, (_, idx) => Buffer.from(`leaf_payload_${idx}`, 'utf8'));
    const startMerkle = process.hrtime.bigint();
    const tree = new MerkleTree(leaves);
    const merkleTime = formatDurationMs(startMerkle);
    console.log(`\n[4] Merkle Tree Construction (${count.toLocaleString()} leaves):`);
    console.log(`    Total Time:  ${merkleTime}`);
    console.log(`    Root Hash:   0x${tree.root.toString('hex').substring(0, 16)}...`);
  }

  // 5. Ed25519 Policy Approval Envelope Signature Benchmark
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const approverPubkey = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const approverHex = approverPubkey.toString('hex');

  const N_APPROVAL = 1_000;
  const startApprove = process.hrtime.bigint();
  for (let i = 0; i < N_APPROVAL; i++) {
    const params = {
      incidentId: Buffer.alloc(16, 1),
      protectedScope: 'public.users',
      targetVersionId: Buffer.alloc(16, 2),
      proposedChangesHash: Buffer.alloc(32, 3),
      requesterId: 'operator@example.com',
      approverPubkey,
      nonce: Buffer.alloc(16, i),
      expiresAtUs: 3000000000000000n,
    };
    const payload = encodeApprovalPayload(params);
    const signature = crypto.sign(null, payload, privateKey);
    verifyApprovalEnvelope({ ...params, signature }, [approverHex], 1000000000000000n);
  }
  const approveTime = formatDurationMs(startApprove);
  console.log(`\n[5] Ed25519 Policy Approval Verification (${N_APPROVAL.toLocaleString()} ops):`);
  console.log(`    Total Time: ${approveTime}`);
  console.log(`    Throughput: ${Math.round((N_APPROVAL / (Number(process.hrtime.bigint() - startApprove) / 1e9))).toLocaleString()} approvals/sec`);

  console.log('\n====================================================\n');
}

runBenchmark();
