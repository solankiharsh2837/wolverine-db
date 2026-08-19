import crypto from 'node:crypto';
import { canonicalizeJson } from '../binary/c14n.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface AgentAttestation {
  agentNodeId: string;
  agentPubkeyHex: string;
  signatureHex: string;
  lsn: string;
}

export interface CustomerAuthorization {
  keyId: string;
  customerPubkeyHex: string;
  signatureHex: string;
  commitSeq: bigint;
}

export interface CanonicalCommitment {
  commitmentId: string;
  tenantId: string;
  databaseId: string;
  epoch: number;
  commitSeq: bigint;
  checkpointDigestHex: string;
  stateMerkleRootHex: string;
  changeChainHeadHex: string;
  logicalTimestampUs: bigint;
  lsn: string;
  previousCommitmentDigestHex: string;
  agentAttestation: AgentAttestation;
  customerAuthorization: CustomerAuthorization;
}

export interface UnsignedCommitmentPayload {
  commitmentId: string;
  tenantId: string;
  databaseId: string;
  epoch: number;
  commitSeq: string;
  checkpointDigestHex: string;
  stateMerkleRootHex: string;
  changeChainHeadHex: string;
  logicalTimestampUs: string;
  lsn: string;
  previousCommitmentDigestHex: string;
}

/**
 * Computes the deterministic canonical digest D_n over a commitment payload.
 */
export function computeCanonicalCommitmentDigest(commitment: CanonicalCommitment | UnsignedCommitmentPayload): Buffer {
  const payload: UnsignedCommitmentPayload = {
    commitmentId: commitment.commitmentId,
    tenantId: commitment.tenantId,
    databaseId: commitment.databaseId,
    epoch: commitment.epoch,
    commitSeq: commitment.commitSeq.toString(),
    checkpointDigestHex: commitment.checkpointDigestHex,
    stateMerkleRootHex: commitment.stateMerkleRootHex,
    changeChainHeadHex: commitment.changeChainHeadHex,
    logicalTimestampUs: commitment.logicalTimestampUs.toString(),
    lsn: commitment.lsn,
    previousCommitmentDigestHex: commitment.previousCommitmentDigestHex,
  };

  const canonicalJson = canonicalizeJson(payload);
  const preimage = Buffer.concat([
    Buffer.from('WDB:COMMITMENT:v2:', 'utf8'),
    Buffer.from(canonicalJson, 'utf8'),
  ]);

  return crypto.createHash('sha256').update(preimage).digest();
}

/**
 * Computes the message digest for agent enclave attestation.
 */
export function computeAgentAttestationDigest(commitmentDigest: Buffer, lsn: string): Buffer {
  const lsnBuf = Buffer.from(lsn, 'utf8');
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16BE(lsnBuf.length, 0);

  const preimage = Buffer.concat([
    Buffer.from('WDB:AGENT_ATTEST:v1:', 'utf8'),
    commitmentDigest,
    lenBuf,
    lsnBuf,
  ]);

  return crypto.createHash('sha256').update(preimage).digest();
}

/**
 * Computes the message digest for customer root authority authorization.
 */
export function computeCustomerAuthorizationDigest(commitmentDigest: Buffer, commitSeq: bigint): Buffer {
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(commitSeq, 0);

  const preimage = Buffer.concat([
    Buffer.from('WDB:CUST_AUTH:v1:', 'utf8'),
    commitmentDigest,
    seqBuf,
  ]);

  return crypto.createHash('sha256').update(preimage).digest();
}

/**
 * Independently verifies dual cryptographic attestation (Agent Enclave + Customer Authority).
 */
export function verifyDualAttestation(
  commitment: CanonicalCommitment,
  expectedAgentPubkey?: Buffer,
  expectedCustomerPubkey?: Buffer
): { valid: boolean; commitmentDigest: Buffer } {
  const commitmentDigest = computeCanonicalCommitmentDigest(commitment);

  // 1. Verify Agent Enclave Signature
  const agentPubkeyBuf = Buffer.from(commitment.agentAttestation.agentPubkeyHex, 'hex');
  if (expectedAgentPubkey && !agentPubkeyBuf.equals(expectedAgentPubkey)) {
    throw new WolverineError(
      WolverineErrorCode.UNAUTHORIZED_MUTATION,
      `Agent public key mismatch: expected ${expectedAgentPubkey.toString('hex')}, observed ${commitment.agentAttestation.agentPubkeyHex}`
    );
  }

  const agentDigest = computeAgentAttestationDigest(commitmentDigest, commitment.agentAttestation.lsn);
  const agentSigBuf = Buffer.from(commitment.agentAttestation.signatureHex, 'hex');

  const agentKeyObject = crypto.createPublicKey({
    key: agentPubkeyBuf,
    format: 'der',
    type: 'spki',
  });

  const agentValid = crypto.verify(null, agentDigest, agentKeyObject, agentSigBuf);
  if (!agentValid) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
      'Agent enclave attestation signature verification failed'
    );
  }

  // 2. Verify Customer Authority Signature
  const customerPubkeyBuf = Buffer.from(commitment.customerAuthorization.customerPubkeyHex, 'hex');
  if (expectedCustomerPubkey && !customerPubkeyBuf.equals(expectedCustomerPubkey)) {
    throw new WolverineError(
      WolverineErrorCode.UNAUTHORIZED_MUTATION,
      `Customer public key mismatch: expected ${expectedCustomerPubkey.toString('hex')}, observed ${commitment.customerAuthorization.customerPubkeyHex}`
    );
  }

  const customerDigest = computeCustomerAuthorizationDigest(commitmentDigest, commitment.customerAuthorization.commitSeq);
  const customerSigBuf = Buffer.from(commitment.customerAuthorization.signatureHex, 'hex');

  const customerKeyObject = crypto.createPublicKey({
    key: customerPubkeyBuf,
    format: 'der',
    type: 'spki',
  });

  const customerValid = crypto.verify(null, customerDigest, customerKeyObject, customerSigBuf);
  if (!customerValid) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
      'Customer root authorization signature verification failed'
    );
  }

  return { valid: true, commitmentDigest };
}
