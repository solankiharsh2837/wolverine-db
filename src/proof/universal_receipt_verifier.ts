import crypto from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  Hex,
  hashTypedData,
  keccak256,
} from 'viem';
import {
  UniversalTrustReceipt,
  computeReceiptDigest,
} from '../receipts/universal_receipt.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import { canonicalizeJson } from '../binary/c14n.js';
import {
  WOLVERINE_EIP712_DOMAIN_NAME,
  WOLVERINE_EIP712_VERSION,
  EIP712_TYPES,
  formatHex16,
  formatHex32,
  computeAgentAttestPreimage,
  computeCanonicalCommitmentDigest,
  CanonicalTrustCommitmentV3,
} from '../protocol/commitment_v3.js';

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
   * Performs full zero-trust offline verification of a Universal Trust Receipt synchronously.
   * Can run entirely on an air-gapped machine with zero network access.
   */
  public static verifyOffline(params: {
    receipt: UniversalTrustReceipt;
    customerAddressOrPublicKey?: string | Buffer;
    customerPublicKey?: Buffer;
    agentPublicKey: Buffer;
    currentDatabaseMerkleRootHex?: string;
    previousReceipt?: UniversalTrustReceipt;
  }): VerificationResult {
    const { receipt, agentPublicKey, currentDatabaseMerkleRootHex, previousReceipt } = params;
    const customerKey = params.customerAddressOrPublicKey ?? params.customerPublicKey;

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

    // 3. Verify Customer Authorization Signature (SECP256k1 EIP-712 or fallback Ed25519)
    if (!customerKey) {
      return {
        isValid: false,
        status: 'INVALID_CUSTOMER_SIGNATURE',
        details: 'Customer key or address was not provided for verification',
      };
    }

    if (typeof customerKey === 'string' || (customerKey instanceof Buffer && customerKey.length === 20)) {
      // SECP256k1 EIP-712 Path
      const expectedAddr = typeof customerKey === 'string'
        ? customerKey
        : `0x${customerKey.toString('hex')}`;

      try {
        const domain = {
          name: WOLVERINE_EIP712_DOMAIN_NAME,
          version: WOLVERINE_EIP712_VERSION,
          chainId: BigInt(receipt.trustPlane.chainId),
          verifyingContract: receipt.trustPlane.contractAddress as `0x${string}`,
        } as const;

        const message = {
          tenantId: receipt.tenantId,
          databaseId: receipt.databaseId,
          commitSeq: BigInt(receipt.evidencePlane.commitSeq),
          epoch: 1,
          checkpointId: formatHex16(receipt.evidencePlane.checkpointId),
          checkpointDigest: formatHex32(receipt.evidencePlane.checkpointDigestHex),
          stateMerkleRoot: formatHex32(receipt.evidencePlane.stateMerkleRootHex),
          changeChainHead: formatHex32(receipt.evidencePlane.changeChainHeadHex),
          previousCommitmentDigest: formatHex32(receipt.trustPlane.previousCommitmentDigestHex),
          logicalTimestampUs: BigInt(receipt.timestampUs),
          lsn: receipt.evidencePlane.lsn,
          agentId: receipt.evidencePlane.agentId ?? 'agent_node_01',
        };

        const structDigest = hashTypedData({
          domain,
          types: EIP712_TYPES,
          primaryType: 'StateCommitment',
          message,
        });

        const custSigHex = receipt.evidencePlane.customerAuthorizationHex.startsWith('0x')
          ? receipt.evidencePlane.customerAuthorizationHex.slice(2)
          : receipt.evidencePlane.customerAuthorizationHex;

        if (custSigHex.length !== 130) {
          return {
            isValid: false,
            status: 'INVALID_CUSTOMER_SIGNATURE',
            details: `Invalid customer signature length: ${custSigHex.length} chars (expected 130)`,
          };
        }

        const compactSig = custSigHex.slice(0, 128);
        const v = parseInt(custSigHex.slice(128, 130), 16);
        const recovery = v >= 27 ? v - 27 : v;

        const point = secp256k1.Signature.fromCompact(compactSig)
          .addRecoveryBit(recovery)
          .recoverPublicKey(structDigest.slice(2));

        const pubBytes = point.toRawBytes(false);
        const recoveredAddr = `0x${keccak256(pubBytes.slice(1)).slice(-40)}`;

        if (recoveredAddr.toLowerCase() !== expectedAddr.toLowerCase()) {
          return {
            isValid: false,
            status: 'INVALID_CUSTOMER_SIGNATURE',
            details: `Customer EIP-712 signature mismatch: expected ${expectedAddr}, recovered ${recoveredAddr}`,
          };
        }
      } catch (err: any) {
        return {
          isValid: false,
          status: 'INVALID_CUSTOMER_SIGNATURE',
          details: `Customer EIP-712 signature verification error: ${err.message}`,
        };
      }
    } else {
      // Legacy Ed25519 fallback for older receipts
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
          customerKey.subarray(-32),
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
    }

    // 4. Verify Agent Attestation Signature (Ed25519)
    try {
      const canonicalCommitment: CanonicalTrustCommitmentV3 = {
        protocolVersion: 3,
        tenantId: receipt.tenantId,
        databaseId: receipt.databaseId,
        checkpointId: receipt.evidencePlane.checkpointId,
        commitSeq: BigInt(receipt.evidencePlane.commitSeq),
        epoch: 1,
        chainId: receipt.trustPlane.chainId,
        contractAddress: receipt.trustPlane.contractAddress,
        networkId: receipt.trustPlane.networkId,
        checkpointDigestHex: receipt.evidencePlane.checkpointDigestHex,
        stateMerkleRootHex: receipt.evidencePlane.stateMerkleRootHex,
        changeChainHeadHex: receipt.evidencePlane.changeChainHeadHex,
        previousCommitmentDigestHex: receipt.trustPlane.previousCommitmentDigestHex,
        logicalTimestampUs: BigInt(receipt.timestampUs),
        lsn: receipt.evidencePlane.lsn,
        agentId: receipt.evidencePlane.agentId ?? 'agent_node_01',
        customerSigningAddress: typeof customerKey === 'string'
          ? customerKey
          : `0x${customerKey.toString('hex')}`,
      };

      const expectedCommitmentDigest = computeCanonicalCommitmentDigest(canonicalCommitment);
      const agentPreimage = computeAgentAttestPreimage(canonicalCommitment, expectedCommitmentDigest);

      const rawAgentSig = Buffer.from(
        receipt.evidencePlane.agentAttestationHex.startsWith('0x')
          ? receipt.evidencePlane.agentAttestationHex.slice(2)
          : receipt.evidencePlane.agentAttestationHex,
        'hex'
      );
      const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
      const spkiKey = Buffer.concat([spkiHeader, agentPublicKey.subarray(-32)]);
      const agentKeyObj = crypto.createPublicKey({ key: spkiKey, format: 'der', type: 'spki' });

      const isAgentValid = crypto.verify(null, agentPreimage, agentKeyObj, rawAgentSig);
      if (!isAgentValid) {
        // Try v2 fallback
        const commitDigestBuf = Buffer.from(receipt.evidencePlane.checkpointDigestHex, 'hex');
        const legacyAgentPreimage = Buffer.concat([
          Buffer.from('WDB:AGENT_ATTEST:v2:', 'utf8'),
          commitDigestBuf,
          Buffer.from(receipt.evidencePlane.lsn, 'utf8'),
        ]);
        const isLegacyValid = crypto.verify(null, legacyAgentPreimage, agentKeyObj, rawAgentSig);
        if (!isLegacyValid) {
          return {
            isValid: false,
            status: 'INVALID_AGENT_SIGNATURE',
            details: 'Evidence agent attestation signature failed cryptographic verification',
          };
        }
      }
    } catch (err: any) {
      return {
        isValid: false,
        status: 'INVALID_AGENT_SIGNATURE',
        details: `Evidence agent signature verification error: ${err.message}`,
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
