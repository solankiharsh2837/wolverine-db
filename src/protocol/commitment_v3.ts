import crypto from 'node:crypto';
import {
  Hex,
  hashTypedData,
  recoverAddress,
} from 'viem';
import { canonicalizeJson } from '../binary/c14n.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export const PROTOCOL_VERSION_V3 = 3;
export const COMMITMENT_DOMAIN_V3 = 'WDB:COMMIT:v3:';
export const CUST_AUTH_DOMAIN_V3 = 'WDB:CUST_AUTH:v3:';
export const AGENT_ATTEST_DOMAIN_V3 = 'WDB:AGENT_ATTEST:v3:';

export const WOLVERINE_EIP712_DOMAIN_NAME = 'WolverineTrustRegistry';
export const WOLVERINE_EIP712_VERSION = '3';

export const EIP712_TYPES = {
  StateCommitment: [
    { name: 'tenantId', type: 'string' },
    { name: 'databaseId', type: 'string' },
    { name: 'commitSeq', type: 'uint64' },
    { name: 'epoch', type: 'uint32' },
    { name: 'checkpointId', type: 'bytes16' },
    { name: 'checkpointDigest', type: 'bytes32' },
    { name: 'stateMerkleRoot', type: 'bytes32' },
    { name: 'changeChainHead', type: 'bytes32' },
    { name: 'previousCommitmentDigest', type: 'bytes32' },
    { name: 'logicalTimestampUs', type: 'uint64' },
    { name: 'lsn', type: 'string' },
    { name: 'agentId', type: 'string' },
  ],
} as const;

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
 * Normalizes hex strings to 0x-prefixed 32-byte or 16-byte hex representation for EIP-712 typing.
 */
export function formatHex32(hex: string): `0x${string}` {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  return `0x${clean.padStart(64, '0').toLowerCase()}`;
}

export function formatHex16(hex: string): `0x${string}` {
  const clean = hex.replace(/-/g, '').replace(/^0x/, '');
  return `0x${clean.padStart(32, '0').toLowerCase()}`;
}

/**
 * Computes EIP-712 structured typed data hash for a CanonicalTrustCommitmentV3.
 */
export function computeEip712CommitmentDigest(commitment: CanonicalTrustCommitmentV3): `0x${string}` {
  const domain = {
    name: WOLVERINE_EIP712_DOMAIN_NAME,
    version: WOLVERINE_EIP712_VERSION,
    chainId: BigInt(commitment.chainId),
    verifyingContract: commitment.contractAddress as `0x${string}`,
  } as const;

  const message = {
    tenantId: commitment.tenantId,
    databaseId: commitment.databaseId,
    commitSeq: commitment.commitSeq,
    epoch: commitment.epoch,
    checkpointId: formatHex16(commitment.checkpointId),
    checkpointDigest: formatHex32(commitment.checkpointDigestHex),
    stateMerkleRoot: formatHex32(commitment.stateMerkleRootHex),
    changeChainHead: formatHex32(commitment.changeChainHeadHex),
    previousCommitmentDigest: formatHex32(commitment.previousCommitmentDigestHex),
    logicalTimestampUs: commitment.logicalTimestampUs,
    lsn: commitment.lsn,
    agentId: commitment.agentId,
  };

  return hashTypedData({
    domain,
    types: EIP712_TYPES,
    primaryType: 'StateCommitment',
    message,
  });
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
 * Constructs the deterministic preimage for agent attestation signature (Ed25519).
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
 * Verifies customer SECP256k1 EIP-712 signature against commitment and expected address.
 */
export async function verifyCustomerEip712Signature(
  commitment: CanonicalTrustCommitmentV3,
  customerSignatureHex: string,
  expectedAddress: string
): Promise<{ isValid: boolean; recoveredAddress?: string; error?: string }> {
  try {
    const cleanSig = (customerSignatureHex.startsWith('0x')
      ? customerSignatureHex
      : `0x${customerSignatureHex}`) as `0x${string}`;

    const domain = {
      name: WOLVERINE_EIP712_DOMAIN_NAME,
      version: WOLVERINE_EIP712_VERSION,
      chainId: BigInt(commitment.chainId),
      verifyingContract: commitment.contractAddress as `0x${string}`,
    } as const;

    const message = {
      tenantId: commitment.tenantId,
      databaseId: commitment.databaseId,
      commitSeq: commitment.commitSeq,
      epoch: commitment.epoch,
      checkpointId: formatHex16(commitment.checkpointId),
      checkpointDigest: formatHex32(commitment.checkpointDigestHex),
      stateMerkleRoot: formatHex32(commitment.stateMerkleRootHex),
      changeChainHead: formatHex32(commitment.changeChainHeadHex),
      previousCommitmentDigest: formatHex32(commitment.previousCommitmentDigestHex),
      logicalTimestampUs: commitment.logicalTimestampUs,
      lsn: commitment.lsn,
      agentId: commitment.agentId,
    };

    const recovered = await recoverAddress({
      hash: hashTypedData({
        domain,
        types: EIP712_TYPES,
        primaryType: 'StateCommitment',
        message,
      }),
      signature: cleanSig,
    });

    const expectedClean = expectedAddress.toLowerCase();
    const recoveredClean = recovered.toLowerCase();

    if (expectedClean !== recoveredClean) {
      return {
        isValid: false,
        recoveredAddress: recovered,
        error: `Customer address mismatch: expected ${expectedAddress}, recovered ${recovered}`,
      };
    }

    return { isValid: true, recoveredAddress: recovered };
  } catch (err: any) {
    return { isValid: false, error: `Customer signature verification failed: ${err.message}` };
  }
}

/**
 * Verifies that a dual-signed commitment is valid and cryptographically bound.
 */
export async function verifyDualSignedCommitment(
  signed: DualSignedCommitmentV3,
  agentPublicKey: Buffer
): Promise<{ isValid: boolean; error?: string }> {
  const expectedDigest = computeCanonicalCommitmentDigest(signed.commitment);
  const cleanDigest = (d: string) => (d.startsWith('0x') ? d.slice(2).toLowerCase() : d.toLowerCase());

  if (cleanDigest(signed.commitmentDigestHex) !== cleanDigest(expectedDigest)) {
    return {
      isValid: false,
      error: `Commitment digest mismatch: expected ${expectedDigest}, received ${signed.commitmentDigestHex}`,
    };
  }

  // 1. Verify Customer SECP256k1 EIP-712 Signature
  const custRes = await verifyCustomerEip712Signature(
    signed.commitment,
    signed.customerSignatureHex,
    signed.commitment.customerSigningAddress
  );
  if (!custRes.isValid) {
    return { isValid: false, error: custRes.error };
  }

  // 2. Verify Agent Attestation (Ed25519)
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
