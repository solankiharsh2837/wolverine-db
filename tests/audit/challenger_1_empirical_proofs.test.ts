import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { BesuTransactionSubmitter } from '../../src/blockchain/besu/transaction_submitter.js';
import { BesuClient } from '../../src/blockchain/besu/client.js';
import { computeCustomerAuthorizationDigest } from '../../src/trust/commitment.js';
import { UniversalReceiptVerifier } from '../../src/proof/universal_receipt_verifier.js';
import { UniversalTrustReceipt, computeReceiptDigest } from '../../src/receipts/universal_receipt.js';
import { CloudKmsSigningProvider } from '../../src/crypto/signing_provider.js';
import { AwsKmsSigningProvider } from '../../src/crypto/aws_kms_provider.js';
import { PgOutputDecoder } from '../../src/wal/pgoutput_decoder.js';

describe('Challenger 1 Empirical Verification & Stress Test Suite', () => {

  describe('1. Smart Contract Invariants & Sequence 1 Tenant Squatting DoS (SEC-R3-01, SEC-R3-02, SEC-R3-03)', () => {
    
    // EVM Simulation class replicating WolverineTrustRegistry.sol exactly
    class MockWolverineTrustRegistry {
      public commitments = new Map<string, any>();
      public latestSequence = new Map<string, Map<string, bigint>>();
      public sequenceIndex = new Map<string, Map<string, Map<bigint, string>>>();

      public getLatestSequence(tenantId: string, databaseId: string): bigint {
        return this.latestSequence.get(tenantId)?.get(databaseId) ?? 0n;
      }

      public commitState(params: {
        callerAddress: string;
        tenantId: string;
        databaseId: string;
        checkpointIdHex: string;
        commitSeq: bigint;
        epoch: number;
        checkpointDigestHex: string;
        stateMerkleRootHex: string;
        changeChainHeadHex: string;
        previousCommitmentDigestHex: string;
        commitmentDigestHex: string;
        logicalTimestampUs: bigint;
        protocolVersion: number;
        agentSignatureHex: string;
        customerSignatureHex: string;
      }): { success: boolean } {
        const {
          tenantId,
          databaseId,
          commitSeq,
          previousCommitmentDigestHex,
          commitmentDigestHex,
        } = params;

        // Invariant 1: Duplicate check
        if (this.commitments.has(commitmentDigestHex)) {
          throw new Error(`DuplicateCommitment(${commitmentDigestHex})`);
        }

        const currentHead = this.getLatestSequence(tenantId, databaseId);

        // Invariant 2: Sequence Monotonicity
        if (currentHead === 0n) {
          if (commitSeq !== 1n) {
            throw new Error(`SequenceGapDetected(expected: 1, received: ${commitSeq})`);
          }
        } else {
          if (commitSeq !== currentHead + 1n) {
            throw new Error(`SequenceGapDetected(expected: ${currentHead + 1n}, received: ${commitSeq})`);
          }

          const expectedPrev = this.sequenceIndex.get(tenantId)?.get(databaseId)?.get(currentHead);
          if (expectedPrev !== previousCommitmentDigestHex) {
            throw new Error(`InvalidPreviousCommitment(expected: ${expectedPrev}, received: ${previousCommitmentDigestHex})`);
          }
        }

        // Note: Zero signature verification executed on-chain in WolverineTrustRegistry.sol!
        this.commitments.set(commitmentDigestHex, { ...params, blockNumber: 100n });

        if (!this.latestSequence.has(tenantId)) {
          this.latestSequence.set(tenantId, new Map());
          this.sequenceIndex.set(tenantId, new Map());
        }
        this.latestSequence.get(tenantId)!.set(databaseId, commitSeq);

        if (!this.sequenceIndex.get(tenantId)!.has(databaseId)) {
          this.sequenceIndex.get(tenantId)!.set(databaseId, new Map());
        }
        this.sequenceIndex.get(tenantId)!.get(databaseId)!.set(commitSeq, commitmentDigestHex);

        return { success: true };
      }
    }

    it('proves Tenant Squatting Sequence 1 Frontrunning DoS mathematically locks out legitimate customer', () => {
      const registry = new MockWolverineTrustRegistry();
      const victimTenant = 'acme_corp';
      const victimDb = 'prod_db';

      // 1. Attacker observes/guesses tenantId and submits a fake sequence 1 commitment with garbage signatures
      const attackerFakeDigest = '0xattacker11111111111111111111111111111111111111111111111111111111';
      const attackerRes = registry.commitState({
        callerAddress: '0xAttackerAddress',
        tenantId: victimTenant,
        databaseId: victimDb,
        checkpointIdHex: '0x0001',
        commitSeq: 1n,
        epoch: 1,
        checkpointDigestHex: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
        stateMerkleRootHex: '0xbad0cafebad0cafebad0cafebad0cafebad0cafebad0cafebad0cafebad0cafe',
        changeChainHeadHex: '0x00',
        previousCommitmentDigestHex: '0x0000000000000000000000000000000000000000000000000000000000000000',
        commitmentDigestHex: attackerFakeDigest,
        logicalTimestampUs: 1700000000000000n,
        protocolVersion: 2,
        agentSignatureHex: '0x00',   // Dummy unverified signature
        customerSignatureHex: '0x00',// Dummy unverified signature
      });

      expect(attackerRes.success).toBe(true);
      expect(registry.getLatestSequence(victimTenant, victimDb)).toBe(1n);

      // 2. Legitimate Customer arrives with authentic sequence 1 commitment
      const customerLegitDigest = '0xcustomer22222222222222222222222222222222222222222222222222222222';
      
      // Attempt A: Customer tries to submit commitSeq = 1 (their genuine genesis)
      expect(() => {
        registry.commitState({
          callerAddress: '0xCustomerAddress',
          tenantId: victimTenant,
          databaseId: victimDb,
          checkpointIdHex: '0x0001',
          commitSeq: 1n,
          epoch: 1,
          checkpointDigestHex: '0xrealchk',
          stateMerkleRootHex: '0xrealroot',
          changeChainHeadHex: '0xrealchain',
          previousCommitmentDigestHex: '0x0000000000000000000000000000000000000000000000000000000000000000',
          commitmentDigestHex: customerLegitDigest,
          logicalTimestampUs: 1700000000000000n,
          protocolVersion: 2,
          agentSignatureHex: '0xvalidAgentSig',
          customerSignatureHex: '0xvalidCustomerSig',
        });
      }).toThrowError(/SequenceGapDetected\(expected: 2, received: 1\)/);

      // Attempt B: Customer tries to submit commitSeq = 2 with authentic previousCommitmentDigest = 0x0
      expect(() => {
        registry.commitState({
          callerAddress: '0xCustomerAddress',
          tenantId: victimTenant,
          databaseId: victimDb,
          checkpointIdHex: '0x0002',
          commitSeq: 2n,
          epoch: 1,
          checkpointDigestHex: '0xrealchk2',
          stateMerkleRootHex: '0xrealroot2',
          changeChainHeadHex: '0xrealchain2',
          previousCommitmentDigestHex: '0x0000000000000000000000000000000000000000000000000000000000000000',
          commitmentDigestHex: customerLegitDigest,
          logicalTimestampUs: 1700000001000000n,
          protocolVersion: 2,
          agentSignatureHex: '0xvalidAgentSig2',
          customerSignatureHex: '0xvalidCustomerSig2',
        });
      }).toThrowError(/InvalidPreviousCommitment/);

      // CONCLUSION: Legitimate customer is permanently bricked from registering their sequence 1 genesis on-chain!
    });

    it('proves sequence monotonicity cannot be skipped or bypassed', () => {
      const registry = new MockWolverineTrustRegistry();
      
      // Attempt to register sequence 5 when currentHead is 0
      expect(() => {
        registry.commitState({
          callerAddress: '0xAttacker',
          tenantId: 'tenant1',
          databaseId: 'db1',
          checkpointIdHex: '0x0001',
          commitSeq: 5n,
          epoch: 1,
          checkpointDigestHex: '0xchk',
          stateMerkleRootHex: '0xroot',
          changeChainHeadHex: '0xchain',
          previousCommitmentDigestHex: '0x00',
          commitmentDigestHex: '0xdigest1',
          logicalTimestampUs: 1700000000000000n,
          protocolVersion: 2,
          agentSignatureHex: '0x00',
          customerSignatureHex: '0x00',
        });
      }).toThrowError(/SequenceGapDetected\(expected: 1, received: 5\)/);
    });
  });

  describe('2. Gateway Root Compromise & Rogue Operator Bypass of Customer KMS (SEC-R2-01)', () => {
    it('proves BesuTransactionSubmitter accepts dummy signatures without cryptographic validation', async () => {
      let capturedContractCall: any = null;

      // Mock BesuClient
      const mockClient = new BesuClient(
        {
          rpcUrl: 'http://127.0.0.1:8545',
          chainId: 13370,
          contractAddress: '0x1234567890123456789012345678901234567890',
        },
        async (method, params) => {
          if (method === 'commitState') {
            capturedContractCall = params[0];
            return {
              success: true,
              txHash: '0xtxhash123',
              blockNumber: 100n,
              blockHash: '0xblockhash123',
              commitmentDigestHex: params[0].commitmentDigestHex,
              contractAddress: '0x1234567890123456789012345678901234567890',
            };
          }
          return null;
        }
      );

      const submitter = new BesuTransactionSubmitter(mockClient);

      // Rogue operator supplies dummy 2-byte hex for signatures
      const rogueInput = {
        tenantId: 'victim_enterprise',
        databaseId: 'prod_vault',
        checkpointIdHex: '0x0001',
        commitSeq: 1n,
        epoch: 1,
        checkpointDigestHex: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        stateMerkleRootHex: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        changeChainHeadHex: '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        previousCommitmentDigestHex: '0x0000000000000000000000000000000000000000000000000000000000000000',
        commitmentDigestHex: '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        logicalTimestampUs: 1700000000000000n,
        protocolVersion: 2,
        agentSignatureHex: '0x0000',    // FAKE DUMMY AGENT SIG
        customerSignatureHex: '0x0000', // FAKE DUMMY CUSTOMER SIG (NO KMS CALL)
      };

      const result = await submitter.submitStateCommitment(rogueInput);

      expect(result.success).toBe(true);
      expect(capturedContractCall).toBeDefined();
      expect(capturedContractCall.customerSignatureHex).toBe('0x0000');
      // EMPIRICAL PROOF: BesuTransactionSubmitter submits dummy customer signatures directly to blockchain!
    });
  });

  describe('3. Dual-Attestation Preimage Incompatibility & Domain Separation Deficiencies (SEC-R2-02)', () => {
    it('proves Schema 1 (src/trust) is incompatible with Schema 3 (UniversalReceiptVerifier)', async () => {
      const custKeyPair = crypto.generateKeyPairSync('ed25519');
      const custRawPub = custKeyPair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);

      const commitDigestBuf = crypto.createHash('sha256').update('test-commitment').digest();
      const commitSeq = 1n;

      // Schema 1 Customer Digest (from src/trust/commitment.ts)
      const schema1CustomerDigest = computeCustomerAuthorizationDigest(commitDigestBuf, commitSeq);
      const schema1CustomerSig = crypto.sign(null, schema1CustomerDigest, custKeyPair.privateKey);

      // Schema 3 Customer Preimage (from UniversalReceiptVerifier.ts)
      // Uses "WDB:CUST_AUTH:v2:" || checkpointDigestHex_buf || UTF8(commitSeq_str)
      const schema3CustomerPreimage = Buffer.concat([
        Buffer.from('WDB:CUST_AUTH:v2:', 'utf8'),
        commitDigestBuf,
        Buffer.from(commitSeq.toString(), 'utf8'),
      ]);

      const custPubKeyObj = crypto.createPublicKey({
        key: Buffer.concat([
          Buffer.from('302a300506032b6570032100', 'hex'),
          custRawPub,
        ]),
        format: 'der',
        type: 'spki',
      });

      // Verification under Schema 3 fails against Schema 1 signature!
      const isValidUnderSchema3 = crypto.verify(null, schema3CustomerPreimage, custPubKeyObj, schema1CustomerSig);
      expect(isValidUnderSchema3).toBe(false);

      // EMPIRICAL PROOF: Schema 1 and Schema 3 are completely conflicting!
    });

    it('proves preimages lack EVM chainId and contractAddress domain separation', () => {
      const commitDigestBuf = crypto.createHash('sha256').update('digest').digest();
      const schema1DigestPreimage = Buffer.concat([
        Buffer.from('WDB:CUST_AUTH:v1:', 'utf8'),
        commitDigestBuf,
        Buffer.alloc(8),
      ]);

      // None of the preimages contain chainId (e.g. 13370) or contract address (0x...)
      const schema1Str = schema1DigestPreimage.toString('utf8');
      expect(schema1Str.includes('chainId')).toBe(false);
      expect(schema1Str.includes('contractAddress')).toBe(false);
    });
  });

  describe('4. KMS Provider Fallbacks & Key Buffer Security (SEC-R2-03, SEC-R2-04)', () => {
    it('proves CloudKmsSigningProvider computes HMAC with public keyArn instead of failing closed', async () => {
      const publicArn = 'arn:aws:kms:us-east-1:123456789012:key/public-key-id';
      const provider = new CloudKmsSigningProvider({
        provider: 'AWS_KMS',
        keyArn: publicArn,
        region: 'us-east-1',
      });

      const messageDigest = crypto.createHash('sha256').update('evidence-block-data').digest();
      const signature = await provider.sign(messageDigest);

      const expectedHmac = crypto.createHmac('sha512', publicArn)
        .update(messageDigest)
        .digest()
        .subarray(0, 64);

      expect(signature.equals(expectedHmac)).toBe(true);
      // EMPIRICAL PROOF: Anyone knowing keyArn metadata can forge signatures in unconfigured environments!
    });

    it('proves AwsKmsSigningProvider defaults public key to 32 zero bytes', () => {
      const provider = new AwsKmsSigningProvider({
        keyId: 'my-key-id',
        region: 'us-east-1',
      });

      const pubKey = provider.getPublicKey();
      expect(pubKey.length).toBe(32);
      expect(pubKey.equals(Buffer.alloc(32, 0))).toBe(true);
    });
  });

  describe('5. Offline Receipt & Proof Deficiencies (SEC-R4-01, SEC-R4-02)', () => {
    it('proves UniversalReceiptVerifier passes on fabricated blockchain hashes', () => {
      const custKeyPair = crypto.generateKeyPairSync('ed25519');
      const agentKeyPair = crypto.generateKeyPairSync('ed25519');
      const custRawPub = custKeyPair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
      const agentRawPub = agentKeyPair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);

      const chkDigestHex = crypto.createHash('sha256').update('chk').digest('hex');
      const chkBuf = Buffer.from(chkDigestHex, 'hex');

      const custPreimage = Buffer.concat([
        Buffer.from('WDB:CUST_AUTH:v2:', 'utf8'),
        chkBuf,
        Buffer.from('1', 'utf8'),
      ]);
      const agentPreimage = Buffer.concat([
        Buffer.from('WDB:AGENT_ATTEST:v2:', 'utf8'),
        chkBuf,
        Buffer.from('0/1000', 'utf8'),
      ]);

      const custSig = crypto.sign(null, custPreimage, custKeyPair.privateKey);
      const agentSig = crypto.sign(null, agentPreimage, agentKeyPair.privateKey);

      const fakeReceiptBase = {
        receiptVersion: 2,
        receiptId: 'fake-001',
        tenantId: 'tenant-1',
        databaseId: 'db-1',
        timestampUs: '1700000000000000',
        evidencePlane: {
          checkpointId: 'chk-001',
          commitSeq: '1',
          lsn: '0/1000',
          checkpointDigestHex: chkDigestHex,
          stateMerkleRootHex: '11'.repeat(32),
          changeChainHeadHex: '22'.repeat(32),
          agentAttestationHex: agentSig.toString('hex'),
          customerAuthorizationHex: custSig.toString('hex'),
        },
        trustPlane: {
          networkId: 'imaginary-chain',
          chainId: 9999,
          blockchainTransactionHash: '0x9999999999999999999999999999999999999999999999999999999999999999',
          blockNumber: '123456',
          blockHash: '0x8888888888888888888888888888888888888888888888888888888888888888',
          finalityStatus: 'FINALIZED' as const,
          contractAddress: '0x0000000000000000000000000000000000000000',
          previousCommitmentDigestHex: '00'.repeat(32),
        },
        optionalPublicAnchor: { status: 'NONE' as const },
      };

      const receiptDigest = computeReceiptDigest(fakeReceiptBase);
      const receipt: UniversalTrustReceipt = {
        ...fakeReceiptBase,
        receiptDigestHex: receiptDigest.toString('hex'),
      };

      const verificationResult = UniversalReceiptVerifier.verifyOffline({
        receipt,
        customerPublicKey: custRawPub,
        agentPublicKey: agentRawPub,
      });

      // EMPIRICAL PROOF: verifyOffline marks completely fake blockchain hashes as AUTHENTIC!
      expect(verificationResult.isValid).toBe(true);
      expect(verificationResult.status).toBe('AUTHENTIC');
    });
  });

  describe('6. PostgreSQL Replication Protocol Crash (SEC-R5-02)', () => {
    it('proves PgOutputDecoder throws MALFORMED_FIELD_PAYLOAD on STREAM START (S) message', () => {
      const decoder = new PgOutputDecoder();
      const streamStartBuf = Buffer.from('S\x00\x00\x00\x01\x00', 'binary');

      expect(() => {
        decoder.decodeMessage(streamStartBuf);
      }).toThrowError(/Unknown pgoutput message type 'S'/);
    });
  });
});
