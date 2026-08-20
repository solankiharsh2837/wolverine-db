import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256 } from 'viem';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const SECP256K1_HALF_N = SECP256K1_N >> 1n;

export interface KmsParsedSignature {
  r: `0x${string}`;
  s: `0x${string}`;
  v: number;
  isNormalizedLowS: boolean;
  signatureHex: `0x${string}`; // 65 bytes (130 hex chars + 0x)
  recoveredAddress: `0x${string}`;
}

/**
 * Parses ASN.1 DER-encoded ECDSA signature returned by AWS KMS or GCP Cloud KMS,
 * enforces low-s canonicalization, and computes the recovery ID (v in [27, 28])
 * against the known KMS public key / expected EVM address.
 */
export function parseKmsDerSignature(params: {
  derSignature: Buffer | Uint8Array;
  digest: `0x${string}` | Buffer | Uint8Array;
  expectedAddressOrPublicKey: `0x${string}` | Buffer | Uint8Array;
}): KmsParsedSignature {
  const der = Buffer.isBuffer(params.derSignature)
    ? params.derSignature
    : Buffer.from(params.derSignature);

  const digestBuf = typeof params.digest === 'string'
    ? Buffer.from(params.digest.startsWith('0x') ? params.digest.slice(2) : params.digest, 'hex')
    : Buffer.from(params.digest);

  if (digestBuf.length !== 32) {
    throw new WolverineError(
      WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
      `Invalid EIP-712 digest length: ${digestBuf.length} bytes (expected 32)`
    );
  }

  // Derive expected address
  let expectedAddress: string;
  if (typeof params.expectedAddressOrPublicKey === 'string') {
    expectedAddress = params.expectedAddressOrPublicKey.toLowerCase();
  } else {
    const pubBuf = Buffer.from(params.expectedAddressOrPublicKey);
    if (pubBuf.length === 20) {
      expectedAddress = `0x${pubBuf.toString('hex').toLowerCase()}`;
    } else if (pubBuf.length === 65 && pubBuf[0] === 0x04) {
      expectedAddress = `0x${keccak256(pubBuf.subarray(1)).slice(-40).toLowerCase()}`;
    } else if (pubBuf.length === 64) {
      expectedAddress = `0x${keccak256(pubBuf).slice(-40).toLowerCase()}`;
    } else if (pubBuf.length === 33) {
      // Compressed public key -> uncompress
      const point = secp256k1.ProjectivePoint.fromHex(pubBuf);
      const uncompressed = point.toRawBytes(false);
      expectedAddress = `0x${keccak256(uncompressed.slice(1)).slice(-40).toLowerCase()}`;
    } else {
      throw new WolverineError(
        WolverineErrorCode.INVALID_CONFIGURATION,
        `Unrecognized public key / address format of length ${pubBuf.length}`
      );
    }
  }

  // ASN.1 DER Decoding: SEQUENCE { INTEGER r, INTEGER s }
  if (der.length < 8 || der[0] !== 0x30) {
    throw new WolverineError(
      WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
      'Invalid ASN.1 DER signature: missing 0x30 SEQUENCE header'
    );
  }

  let offset = 2;
  // Handle long-form sequence length
  if (der[1]! & 0x80) {
    const lenBytes = der[1]! & 0x7f;
    offset = 2 + lenBytes;
  }

  // 1. Read r
  if (der[offset] !== 0x02) {
    throw new WolverineError(
      WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
      'Invalid ASN.1 DER signature: expected 0x02 INTEGER tag for r'
    );
  }
  const rLen = der[offset + 1]!;
  const rBytes = der.subarray(offset + 2, offset + 2 + rLen);
  offset = offset + 2 + rLen;

  // 2. Read s
  if (der[offset] !== 0x02) {
    throw new WolverineError(
      WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
      'Invalid ASN.1 DER signature: expected 0x02 INTEGER tag for s'
    );
  }
  const sLen = der[offset + 1]!;
  const sBytes = der.subarray(offset + 2, offset + 2 + sLen);

  // Normalize scalars to 32 bytes (strip leading zero if 33 bytes, pad if < 32 bytes)
  const cleanScalar = (buf: Buffer): Buffer => {
    let clean = buf;
    while (clean.length > 32 && clean[0] === 0x00) {
      clean = clean.subarray(1);
    }
    if (clean.length > 32) {
      throw new WolverineError(
        WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
        `ECDSA scalar exceeds 32 bytes: length ${clean.length}`
      );
    }
    if (clean.length < 32) {
      const padded = Buffer.alloc(32, 0);
      clean.copy(padded, 32 - clean.length);
      return padded;
    }
    return clean;
  };

  const rBuf = cleanScalar(rBytes);
  const sBuf = cleanScalar(sBytes);

  let rBig = BigInt(`0x${rBuf.toString('hex')}`);
  let sBig = BigInt(`0x${sBuf.toString('hex')}`);

  if (rBig <= 0n || rBig >= SECP256K1_N || sBig <= 0n || sBig >= SECP256K1_N) {
    throw new WolverineError(
      WolverineErrorCode.MALFORMED_FIELD_PAYLOAD,
      'ECDSA r or s scalar is outside valid secp256k1 curve order (0, n)'
    );
  }

  // Low-s canonicalization (BIP-62 / EIP-2)
  let isNormalizedLowS = false;
  if (sBig > SECP256K1_HALF_N) {
    sBig = SECP256K1_N - sBig;
    isNormalizedLowS = true;
  }

  const rHex = `0x${rBig.toString(16).padStart(64, '0')}` as `0x${string}`;
  const sHex = `0x${sBig.toString(16).padStart(64, '0')}` as `0x${string}`;
  const compactSig = Buffer.from(rHex.slice(2) + sHex.slice(2), 'hex');

  // Derive recovery ID v in [27, 28] by testing candidate recoveries
  let matchedV: number | null = null;
  let matchedAddress: `0x${string}` | null = null;

  for (const recId of [0, 1]) {
    try {
      const point = secp256k1.Signature.fromCompact(compactSig)
        .addRecoveryBit(recId)
        .recoverPublicKey(digestBuf);

      const pubBytes = point.toRawBytes(false);
      const candidateAddr = `0x${keccak256(pubBytes.slice(1)).slice(-40).toLowerCase()}` as `0x${string}`;

      if (candidateAddr.toLowerCase() === expectedAddress.toLowerCase()) {
        matchedV = 27 + recId;
        matchedAddress = candidateAddr;
        break;
      }
    } catch {
      // recovery error on invalid candidate
    }
  }

  if (matchedV === null || matchedAddress === null) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
      `KMS signature public key recovery failed: recovered address did not match expected address ${expectedAddress}`
    );
  }

  const vHex = matchedV.toString(16).padStart(2, '0');
  const signatureHex = `0x${rHex.slice(2)}${sHex.slice(2)}${vHex}` as `0x${string}`;

  return {
    r: rHex,
    s: sHex,
    v: matchedV,
    isNormalizedLowS,
    signatureHex,
    recoveredAddress: matchedAddress,
  };
}
