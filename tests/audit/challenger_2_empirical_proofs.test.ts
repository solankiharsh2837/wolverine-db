import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { UniversalReceiptVerifier } from '../../src/proof/universal_receipt_verifier.js';
import { UniversalTrustReceipt, computeReceiptDigest } from '../../src/receipts/universal_receipt.js';
import { PgLogicalClient } from '../../src/wal/pg_logical_client.js';
import { PgOutputDecoder } from '../../src/wal/pgoutput_decoder.js';
import { WolverineErrorCode } from '../../src/errors/index.js';

describe('Challenger 2 Empirical Verification Suite', () => {
  describe('R4: Offline Verifiability & Receipt Completeness (SEC-R4-01, SEC-R4-02)', () => {
    it('proves UniversalReceiptVerifier accepts fabricated blockchain transaction/block hashes without MPT proofs or QBFT seals', () => {
      // 1. Generate legitimate customer and agent Ed25519 keypairs
      const custKeyPair = crypto.generateKeyPairSync('ed25519');
      const agentKeyPair = crypto.generateKeyPairSync('ed25519');

      const custPubDer = custKeyPair.publicKey.export({ format: 'der', type: 'spki' });
      const agentPubDer = agentKeyPair.publicKey.export({ format: 'der', type: 'spki' });

      const custRawPub = custPubDer.subarray(-32);
      const agentRawPub = agentPubDer.subarray(-32);

      const commitSeq = '1';
      const lsn = '0/16B3748';
      const checkpointDigestHex = crypto.createHash('sha256').update('sample-checkpoint').digest('hex');
      const commitDigestBuf = Buffer.from(checkpointDigestHex, 'hex');

      // Preimage matching UniversalReceiptVerifier.verifyOffline
      const custPreimage = Buffer.concat([
        Buffer.from('WDB:CUST_AUTH:v2:', 'utf8'),
        commitDigestBuf,
        Buffer.from(commitSeq, 'utf8'),
      ]);
      const agentPreimage = Buffer.concat([
        Buffer.from('WDB:AGENT_ATTEST:v2:', 'utf8'),
        commitDigestBuf,
        Buffer.from(lsn, 'utf8'),
      ]);

      const custSig = crypto.sign(null, custPreimage, custKeyPair.privateKey);
      const agentSig = crypto.sign(null, agentPreimage, agentKeyPair.privateKey);

      // 2. Fabricate completely bogus, non-existent blockchain metadata
      const fakeReceiptBase = {
        receiptVersion: 2,
        receiptId: 'fake-receipt-001',
        tenantId: 'tenant-omega',
        databaseId: 'db-omega',
        timestampUs: '1700000000000000',
        evidencePlane: {
          checkpointId: 'chk-001',
          commitSeq,
          lsn,
          checkpointDigestHex,
          stateMerkleRootHex: crypto.createHash('sha256').update('state-root').digest('hex'),
          changeChainHeadHex: crypto.createHash('sha256').update('chain-head').digest('hex'),
          agentAttestationHex: agentSig.toString('hex'),
          customerAuthorizationHex: custSig.toString('hex'),
        },
        trustPlane: {
          networkId: 'completely-fabricated-network',
          chainId: 99999,
          blockchainTransactionHash: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
          blockNumber: '999999999',
          blockHash: '0xbaadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00d',
          finalityStatus: 'FINALIZED' as const,
          contractAddress: '0x0000000000000000000000000000000000000000',
          previousCommitmentDigestHex: '00'.repeat(32),
        },
        optionalPublicAnchor: { status: 'NONE' as const },
      };

      const receiptDigest = computeReceiptDigest(fakeReceiptBase);
      const fakeReceipt: UniversalTrustReceipt = {
        ...fakeReceiptBase,
        receiptDigestHex: receiptDigest.toString('hex'),
      };

      // 3. Run verifyOffline
      const result = UniversalReceiptVerifier.verifyOffline({
        receipt: fakeReceipt,
        customerPublicKey: custRawPub,
        agentPublicKey: agentRawPub,
      });

      // EMPIRICAL PROOF: The verifier marks the fabricated receipt as AUTHENTIC!
      expect(result.isValid).toBe(true);
      expect(result.status).toBe('AUTHENTIC');
      // This proves that v2 receipt has ZERO cryptographic proof of Besu blockchain execution or QBFT consensus seals!
    });
  });

  describe('R5: PostgreSQL CDC Concurrency Race Condition (SEC-R5-01)', () => {
    it('proves shared currentXid in PgLogicalClient causes mutation cross-contamination across interleaved transactions', async () => {
      const client = new PgLogicalClient({
        slotName: 'test_slot',
        publicationName: 'test_pub',
      });

      // Register relation 100: "users" table with "id" column
      // Message format for 'R': 'R' (1B) + relationId (4B) + schema\0 + table\0 + replicaId (1B) + numCols (2B) + [flags(1B) + colName\0 + typeOid(4B) + typeMod(4B)]
      const schemaBuf = Buffer.from('public\0', 'utf8');
      const tableBuf = Buffer.from('users\0', 'utf8');
      const colNameBuf = Buffer.from('id\0', 'utf8');

      const relBuffer = Buffer.alloc(1 + 4 + schemaBuf.length + tableBuf.length + 1 + 2 + (1 + colNameBuf.length + 4 + 4));
      let off = 0;
      relBuffer.write('R', off++);
      relBuffer.writeUInt32BE(100, off); off += 4;
      schemaBuf.copy(relBuffer, off); off += schemaBuf.length;
      tableBuf.copy(relBuffer, off); off += tableBuf.length;
      relBuffer.write('d', off++); // replica identity default
      relBuffer.writeUInt16BE(1, off); off += 2;
      relBuffer.writeUInt8(1, off++); // flags = 1 (PK)
      colNameBuf.copy(relBuffer, off); off += colNameBuf.length;
      relBuffer.writeUInt32BE(23, off); off += 4; // int4
      relBuffer.writeInt32BE(-1, off); off += 4;

      await client.ingestPgOutputMessage(relBuffer);

      // Create Begin message helper: 'B' (1B) + commitLsn (8B) + commitTimeUs (8B) + xid (4B)
      function makeBeginMsg(xid: number, commitLsnBig: bigint): Buffer {
        const buf = Buffer.alloc(1 + 8 + 8 + 4);
        buf.write('B', 0);
        buf.writeBigUInt64BE(commitLsnBig, 1);
        buf.writeBigInt64BE(1700000000000000n, 9);
        buf.writeUInt32BE(xid, 17);
        return buf;
      }

      // Create Insert message helper: 'I' (1B) + relId (4B) + 'N' (1B) + numCols (2B) + colKind 't' (1B) + len (4B) + textVal
      function makeInsertMsg(relId: number, val: string): Buffer {
        const valBuf = Buffer.from(val, 'utf8');
        const buf = Buffer.alloc(1 + 4 + 1 + 2 + 1 + 4 + valBuf.length);
        let o = 0;
        buf.write('I', o++);
        buf.writeUInt32BE(relId, o); o += 4;
        buf.write('N', o++);
        buf.writeUInt16BE(1, o); o += 2;
        buf.write('t', o++);
        buf.writeUInt32BE(valBuf.length, o); o += 4;
        valBuf.copy(buf, o);
        return buf;
      }

      // Create Commit message helper: 'C' (1B) + flags (1B) + commitLsn (8B) + endLsn (8B) + commitTimeUs (8B)
      function makeCommitMsg(commitLsnBig: bigint): Buffer {
        const buf = Buffer.alloc(1 + 1 + 8 + 8 + 8);
        buf.write('C', 0);
        buf.writeUInt8(0, 1);
        buf.writeBigUInt64BE(commitLsnBig, 2);
        buf.writeBigUInt64BE(commitLsnBig + 100n, 10);
        buf.writeBigInt64BE(1700000000000000n, 18);
        return buf;
      }

      // Interleaved scenario:
      // 1. Transaction 1001 begins
      await client.ingestPgOutputMessage(makeBeginMsg(1001, 0x10000000n));

      // 2. Transaction 1002 begins before T1 finishes (interleaved)
      await client.ingestPgOutputMessage(makeBeginMsg(1002, 0x20000000n));

      // 3. Mutation meant for T1 arrives
      await client.ingestPgOutputMessage(makeInsertMsg(100, 'user-1-intended-for-T1'));

      // 4. Now T1 commits
      // When T1 commits, PgLogicalClient uses this.currentXid which was overwritten by T2 (1002)!
      const committedChanges = await client.ingestPgOutputMessage(makeCommitMsg(0x10000000n));

      // The mutation was routed to xid "1002" instead of "1001"!
      expect(committedChanges).toBeDefined();
      expect(committedChanges![0]?.changeRecordData.transactionId).toBe('tx:1002');
      expect((committedChanges![0]?.changeRecordData.provenance as any).xid).toBe('1002');
      // This empirically proves that currentXid overwriting pollutes/swaps mutations across concurrent transactions!
    });
  });

  describe('R5: PostgreSQL 14+ Streaming Replication Protocol Crash (SEC-R5-02)', () => {
    it('proves PgOutputDecoder throws MALFORMED_FIELD_PAYLOAD on STREAM START (S) message', () => {
      const decoder = new PgOutputDecoder();
      const streamStartBuf = Buffer.from('S\x00\x00\x00\x01\x00', 'binary');

      expect(() => {
        decoder.decodeMessage(streamStartBuf);
      }).toThrowError(/Unknown pgoutput message type 'S'/);
    });
  });

  describe('R2: KMS Providers and Fail-Closed Invariants (SEC-R2-03, SEC-R2-04)', () => {
    it('proves CloudKmsSigningProvider computes HMAC simulation using keyArn instead of failing closed', async () => {
      const { CloudKmsSigningProvider } = await import('../../src/crypto/signing_provider.js');
      const provider = new CloudKmsSigningProvider({
        provider: 'AWS_KMS',
        keyArn: 'arn:aws:kms:us-east-1:123456789012:key/public-visible-arn',
        region: 'us-east-1',
      });

      const digest = crypto.createHash('sha256').update('test-payload').digest();
      const signature = await provider.sign(digest);

      // Expected deterministic HMAC using keyArn as key
      const expectedHmac = crypto.createHmac('sha512', 'arn:aws:kms:us-east-1:123456789012:key/public-visible-arn')
        .update(digest)
        .digest()
        .subarray(0, 64);

      expect(signature.equals(expectedHmac)).toBe(true);
      // This empirically proves that anyone with the public ARN can forge KMS signatures in unconfigured environments!
    });

    it('proves AwsKmsSigningProvider defaults uninitialized public key to 32 zero bytes', async () => {
      const { AwsKmsSigningProvider } = await import('../../src/crypto/aws_kms_provider.js');
      const provider = new AwsKmsSigningProvider({
        keyId: 'test-key-id',
        region: 'us-east-1',
      });

      const pubKey = provider.getPublicKey();
      expect(pubKey.length).toBe(32);
      expect(pubKey.equals(Buffer.alloc(32, 0))).toBe(true);
    });
  });

  describe('R2: Dual-Attestation Schema Incompatibility (SEC-R2-02)', () => {
    it('proves signatures created with canonical computeCustomerAuthorizationDigest fail UniversalReceiptVerifier.verifyOffline', async () => {
      const { computeCustomerAuthorizationDigest } = await import('../../src/trust/commitment.js');
      
      const custKeyPair = crypto.generateKeyPairSync('ed25519');
      const agentKeyPair = crypto.generateKeyPairSync('ed25519');
      const custRawPub = custKeyPair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
      const agentRawPub = agentKeyPair.publicKey.export({ format: 'der', type: 'spki' });

      const commitSeq = '1';
      const lsn = '0/16B3748';
      const checkpointDigestHex = crypto.createHash('sha256').update('sample-checkpoint').digest('hex');
      const commitDigestBuf = Buffer.from(checkpointDigestHex, 'hex');

      // Canonical schema from src/trust/commitment.ts:
      // Uses "WDB:CUST_AUTH:v1:" (16B) || digest (32B) || BigEndian_u64(commitSeq) (8B) [56 Bytes]
      const canonicalCustDigest = computeCustomerAuthorizationDigest(commitDigestBuf, 1n);
      const custSig = crypto.sign(null, canonicalCustDigest, custKeyPair.privateKey);

      // Fabricate matching agent sig
      const agentPreimage = Buffer.concat([
        Buffer.from('WDB:AGENT_ATTEST:v2:', 'utf8'),
        commitDigestBuf,
        Buffer.from(lsn, 'utf8'),
      ]);
      const agentSig = crypto.sign(null, agentPreimage, agentKeyPair.privateKey);

      const receiptBase = {
        receiptVersion: 2,
        receiptId: 'schema-mismatch-receipt',
        tenantId: 'tenant-test',
        databaseId: 'db-test',
        timestampUs: '1700000000000000',
        evidencePlane: {
          checkpointId: 'chk-001',
          commitSeq,
          lsn,
          checkpointDigestHex,
          stateMerkleRootHex: crypto.createHash('sha256').update('state-root').digest('hex'),
          changeChainHeadHex: crypto.createHash('sha256').update('chain-head').digest('hex'),
          agentAttestationHex: agentSig.toString('hex'),
          customerAuthorizationHex: custSig.toString('hex'),
        },
        trustPlane: {
          networkId: 'besu',
          chainId: 13370,
          blockchainTransactionHash: '0x1111111111111111111111111111111111111111111111111111111111111111',
          blockNumber: '100',
          blockHash: '0x2222222222222222222222222222222222222222222222222222222222222222',
          finalityStatus: 'FINALIZED' as const,
          contractAddress: '0x0000000000000000000000000000000000000000',
          previousCommitmentDigestHex: '00'.repeat(32),
        },
        optionalPublicAnchor: { status: 'NONE' as const },
      };

      const receiptDigest = computeReceiptDigest(receiptBase);
      const receipt: UniversalTrustReceipt = {
        ...receiptBase,
        receiptDigestHex: receiptDigest.toString('hex'),
      };

      const result = UniversalReceiptVerifier.verifyOffline({
        receipt,
        customerPublicKey: custRawPub,
        agentPublicKey: agentRawPub.subarray(-32),
      });

      // The signature fails because UniversalReceiptVerifier uses "WDB:CUST_AUTH:v2:" + UTF8 string commitSeq!
      expect(result.isValid).toBe(false);
      expect(result.status).toBe('INVALID_CUSTOMER_SIGNATURE');
    });
  });
});
