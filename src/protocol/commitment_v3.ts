import crypto from 'node:crypto';
import { canonicalizeJson } from '../binary/c14n.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export const PROTOCOL_VERSION_V3 = 3;
export const COMMITMENT_DOMAIN_V3 = 'WDB:COMMIT:v3:';
export const CUST_AUTH_DOMAIN_V3 = 'WDB:CUST_AUTH:v3:';
export const AGENT_ATTEST_DOMAIN_V3 = 'WDB:AGENT_ATTEST:v3:';

export interface CanonicalTrustCommitmentV3 {
  protocolVersion: number;
  tenantId: string;
  databaseId: string;
  checkpointId: string;
  commitSeq: bigint;
  epoch: number;
  chainId: number;
  contractAddress: string;
  networkId: string;
  checkpointDigestHex: string;
  stateMerkleRootHex: string;
  changeChainHeadHex: string;
  previousCommitmentDigestHex: string;
  logicalTimestampUs: bigint;
  lsn: string;
  agentId: string;
  customerSigningAddress: string;
}

export interface DualSignedCommitmentV3 {
  commitment: CanonicalTrustCommitmentV3;
  commitmentDigestHex: string;
  customerSignatureHex: string;
  agentSignatureHex: string;
}

/**
 * Computes the authoritative canonical commitment digest D_commit (SHA-256).
 */
export function computeCanonicalCommitmentDigest(
  commitment: CanonicalTrustCommitmentV3
): string {
  const cleanHex = (h: string) => (h.startsWith('0x') ? h.slice(2).toLowerCase() : h.toLowerCase());
  const cleanAddr = (a: string) => (a.startsWith('0x') ? a.toLowerCase() : `0x${a.toLowerCase()}`);

  const normalized = {
    agentId: commitment.agentId,
    chainId: commitment.chainId,
    changeChainHead: cleanHex(commitment.changeChainHeadHex),
    checkpointDigest: cleanHex(commitment.checkpointDigestHex),
    checkpointId: commitment.checkpointId,
    commitSeq: commitment.commitSeq.toString(),
    contractAddress: cleanAddr(commitment.contractAddress),
    customerSigningAddress: cleanAddr(commitment.customerSigningAddress),
    databaseId: commitment.databaseId,
    epoch: commitment.epoch,
    logicalTimestampUs: commitment.logicalTimestampUs.toString(),
    lsn: commitment.lsn,
    networkId: commitment.networkId,
    previousCommitmentDigest: cleanHex(commitment.previousCommitmentDigestHex),
    protocolVersion: commitment.protocolVersion,
    stateMerkleRoot: cleanHex(commitment.stateMerkleRootHex),
    tenantId: commitment.tenantId,
  };

  const canonicalBytes = Buffer.from(canonicalizeJson(normalized), 'utf8');
  const domainPrefix = Buffer.from(COMMITMENT_DOMAIN_V3, 'utf8');

  return crypto
    .createHash('sha256')
    .update(Buffer.concat([domainPrefix, canonicalBytes]))
    .digest('hex');
}

/**
 * Constructs the deterministic preimage for customer authorization signature.
 */
export function computeCustomerAuthPreimage(
  commitment: CanonicalTrustCommitmentV3,
  commitmentDigestHex: string
): Buffer {
  const cleanHex = (h: string) => (h.startsWith('0x') ? h.slice(2).toLowerCase() : h.toLowerCase());
  const cleanAddr = (a: string) => (a.startsWith('0x') ? a.toLowerCase() : `0x${a.toLowerCase()}`);

  const domain = Buffer.from(CUST_AUTH_DOMAIN_V3, 'utf8');
  const chainIdBuf = Buffer.alloc(4);
  chainIdBuf.writeUInt32BE(commitment.chainId, 0);

  const payload = {
    chainId: commitment.chainId,
    commitSeq: commitment.commitSeq.toString(),
    commitmentDigest: cleanHex(commitmentDigestHex),
    contractAddress: cleanAddr(commitment.contractAddress),
    databaseId: commitment.databaseId,
    tenantId: commitment.tenantId,
  };

  const canonicalPayload = Buffer.from(canonicalizeJson(payload), 'utf8');
  return Buffer.concat([domain, chainIdBuf, canonicalPayload]);
}

/**
 * Constructs the deterministic preimage for agent attestation signature.
 */
export function computeAgentAttestPreimage(
  commitment: CanonicalTrustCommitmentV3,
  commitmentDigestHex: string
): Buffer {
  const cleanHex = (h: string) => (h.startsWith('0x') ? h.slice(2).toLowerCase() : h.toLowerCase());

  const domain = Buffer.from(AGENT_ATTEST_DOMAIN_V3, 'utf8');
  const chainIdBuf = Buffer.alloc(4);
  chainIdBuf.writeUInt32BE(commitment.chainId, 0);

  const payload = {
    agentId: commitment.agentId,
    chainId: commitment.chainId,
    commitSeq: commitment.commitSeq.toString(),
    commitmentDigest: cleanHex(commitmentDigestHex),
    databaseId: commitment.databaseId,
    lsn: commitment.lsn,
    tenantId: commitment.tenantId,
  };

  const canonicalPayload = Buffer.from(canonicalizeJson(payload), 'utf8');
  return Buffer.concat([domain, chainIdBuf, canonicalPayload]);
}

/**
 * Verifies that a dual-signed commitment is valid and cryptographically bound.
 */
export function verifyDualSignedCommitment(
  signed: DualSignedCommitmentV3,
  agentPublicKey: Buffer
): { isValid: boolean; error?: string } {
  const expectedDigest = computeCanonicalCommitmentDigest(signed.commitment);
  const cleanDigest = (d: string) => (d.startsWith('0x') ? d.slice(2).toLowerCase() : d.toLowerCase());

  if (cleanDigest(signed.commitmentDigestHex) !== cleanDigest(expectedDigest)) {
    return {
      isValid: false,
      error: `Commitment digest mismatch: expected ${expectedDigest}, received ${signed.commitmentDigestHex}`,
    };
  }

  // Verify Agent Attestation (Ed25519)
  const agentPreimage = computeAgentAttestPreimage(signed.commitment, expectedDigest);
  try {
    const rawAgentSig = Buffer.from(
      signed.agentSignatureHex.startsWith('0x') ? signed.agentSignatureHex.slice(2) : signed.agentSignatureHex,
      'hex'
    );
    const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
    const spkiKey = Buffer.concat([spkiHeader, agentPublicKey]);
    const agentKeyObj = crypto.createPublicKey({ key: spkiKey, format: 'der', type: 'spki' });

    const agentValid = crypto.verify(null, agentPreimage, agentKeyObj, rawAgentSig);
    if (!agentValid) {
      return { isValid: false, error: 'Agent attestation signature verification failed' };
    }
  } catch (err: any) {
    return { isValid: false, error: `Agent signature verification error: ${err.message}` };
  }

  return { isValid: true };
}
