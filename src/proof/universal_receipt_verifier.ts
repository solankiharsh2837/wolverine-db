import crypto from 'node:crypto';
import {
  UniversalTrustReceipt,
  computeReceiptDigest,
} from '../receipts/universal_receipt.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import { canonicalizeJson } from '../binary/c14n.js';

export interface VerificationResult {
  isValid: boolean;
  status:
    | 'AUTHENTIC'
    | 'LOCAL_TAMPERING_DETECTED'
    | 'INVALID_CUSTOMER_SIGNATURE'
    | 'INVALID_AGENT_SIGNATURE'
    | 'RECEIPT_CORRUPTED'
    | 'SEQUENCE_DISCONTINUITY'
    | 'BLOCKCHAIN_BINDING_MISMATCH';
  details?: string;
  witnessedStateMerkleRootHex?: string;
  evaluatedStateMerkleRootHex?: string;
}

export class UniversalReceiptVerifier {
  /**
   * Computes expected commitment digest from evidence plane fields.
   */
  public static computeEvidenceCommitmentDigest(
    tenantId: string,
    databaseId: string,
    evidence: UniversalTrustReceipt['evidencePlane']
  ): Buffer {
    const domain = Buffer.from('WDB:TRUST_COMMITMENT:v2:', 'utf8');
    const canonicalPayload = canonicalizeJson({
      tenantId,
      databaseId,
      checkpointId: evidence.checkpointId,
      commitSeq: evidence.commitSeq,
      checkpointDigestHex: evidence.checkpointDigestHex,
      stateMerkleRootHex: evidence.stateMerkleRootHex,
      changeChainHeadHex: evidence.changeChainHeadHex,
      lsn: evidence.lsn,
    });

    return crypto
      .createHash('sha256')
      .update(Buffer.concat([domain, Buffer.from(canonicalPayload, 'utf8')]))
      .digest();
  }

  /**
   * Performs full zero-trust offline verification of a Universal Trust Receipt.
   * Can run entirely on an air-gapped machine with zero network access.
   */
  public static verifyOffline(params: {
    receipt: UniversalTrustReceipt;
    customerPublicKey: Buffer;
    agentPublicKey: Buffer;
    currentDatabaseMerkleRootHex?: string;
    previousReceipt?: UniversalTrustReceipt;
  }): VerificationResult {
    const { receipt, customerPublicKey, agentPublicKey, currentDatabaseMerkleRootHex, previousReceipt } = params;

    // 1. Verify Receipt Self-Consistency & Digest
    const computedDigest = computeReceiptDigest(receipt);
    const claimedDigest = Buffer.from(receipt.receiptDigestHex, 'hex');

    if (!timingSafeEqualHashes(computedDigest, claimedDigest)) {
      return {
        isValid: false,
        status: 'RECEIPT_CORRUPTED',
        details: 'Receipt internal SHA-256 digest does not match content',
      };
    }

    // 2. Verify Sequence Continuity if previous receipt is supplied
    if (previousReceipt) {
      const prevSeq = BigInt(previousReceipt.evidencePlane.commitSeq);
      const currSeq = BigInt(receipt.evidencePlane.commitSeq);
      if (currSeq !== prevSeq + 1n) {
        return {
          isValid: false,
          status: 'SEQUENCE_DISCONTINUITY',
          details: `Sequence discontinuity: expected ${prevSeq + 1n}, observed ${currSeq}`,
        };
      }
    }

    // 3. Verify Customer Authorization Signature
    // σ_customer = Sign(commitmentDigest || commitSeq)
    const commitDigestBuf = Buffer.from(receipt.evidencePlane.checkpointDigestHex, 'hex');
    const custPreimage = Buffer.concat([
      Buffer.from('WDB:CUST_AUTH:v2:', 'utf8'),
      commitDigestBuf,
      Buffer.from(receipt.evidencePlane.commitSeq, 'utf8'),
    ]);

    const custSig = Buffer.from(receipt.evidencePlane.customerAuthorizationHex, 'hex');
    const custPubKeyObj = crypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        customerPublicKey.subarray(-32),
      ]),
      format: 'der',
      type: 'spki',
    });

    const isCustValid = crypto.verify(null, custPreimage, custPubKeyObj, custSig);
    if (!isCustValid) {
      return {
        isValid: false,
        status: 'INVALID_CUSTOMER_SIGNATURE',
        details: 'Customer authorization signature failed cryptographic verification',
      };
    }

    // 4. Verify Agent Attestation Signature
    // σ_agent = Sign(commitmentDigest || WAL_LSN)
    const agentPreimage = Buffer.concat([
      Buffer.from('WDB:AGENT_ATTEST:v2:', 'utf8'),
      commitDigestBuf,
      Buffer.from(receipt.evidencePlane.lsn, 'utf8'),
    ]);

    const agentSig = Buffer.from(receipt.evidencePlane.agentAttestationHex, 'hex');
    const agentPubKeyObj = crypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        agentPublicKey.subarray(-32),
      ]),
      format: 'der',
      type: 'spki',
    });

    const isAgentValid = crypto.verify(null, agentPreimage, agentPubKeyObj, agentSig);
    if (!isAgentValid) {
      return {
        isValid: false,
        status: 'INVALID_AGENT_SIGNATURE',
        details: 'Evidence agent attestation signature failed cryptographic verification',
      };
    }

    // 5. Verify Blockchain Finality Field Invariants
    if (
      !receipt.trustPlane.blockchainTransactionHash ||
      receipt.trustPlane.blockchainTransactionHash === '' ||
      !receipt.trustPlane.blockHash ||
      receipt.trustPlane.finalityStatus !== 'FINALIZED'
    ) {
      return {
        isValid: false,
        status: 'BLOCKCHAIN_BINDING_MISMATCH',
        details: 'Trust plane does not contain finalized Besu block binding',
      };
    }

    // 6. Check Database State Integrity vs Live Merkle Root
    if (currentDatabaseMerkleRootHex) {
      const witnessedRoot = receipt.evidencePlane.stateMerkleRootHex.toLowerCase();
      const liveRoot = currentDatabaseMerkleRootHex.toLowerCase();

      if (witnessedRoot !== liveRoot) {
        return {
          isValid: false,
          status: 'LOCAL_TAMPERING_DETECTED',
          details: 'Live database state Merkle root does NOT match externally witnessed trust receipt root',
          witnessedStateMerkleRootHex: witnessedRoot,
          evaluatedStateMerkleRootHex: liveRoot,
        };
      }
    }

    return {
      isValid: true,
      status: 'AUTHENTIC',
      witnessedStateMerkleRootHex: receipt.evidencePlane.stateMerkleRootHex,
      evaluatedStateMerkleRootHex: currentDatabaseMerkleRootHex,
    };
  }
}
