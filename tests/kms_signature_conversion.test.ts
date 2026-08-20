import { describe, it, expect } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256, hashTypedData } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { parseKmsDerSignature, SECP256K1_N, SECP256K1_HALF_N } from '../src/crypto/kms_der_parser.js';
import { WolverineError, WolverineErrorCode } from '../src/errors/index.js';
import {
  WOLVERINE_EIP712_DOMAIN_NAME,
  WOLVERINE_EIP712_VERSION,
  EIP712_TYPES,
  formatHex16,
  formatHex32,
} from '../src/protocol/commitment_v3.js';

describe('Cloud KMS DER Signature Conversion & Canonicalization', () => {
  const privKey = '0x0000000000000000000000000000000000000000000000000000000000000042' as `0x${string}`;
  const account = privateKeyToAccount(privKey);
  const expectedAddress = account.address;

  const testDigest = keccak256(Buffer.from('wolverine_kms_test_digest'));

  // Helper to construct DER SEQUENCE { INTEGER r, INTEGER s }
  function encodeDer(rBig: bigint, sBig: bigint): Buffer {
    const encodeInt = (val: bigint): Buffer => {
      let hex = val.toString(16);
      if (hex.length % 2 !== 0) hex = '0' + hex;
      let buf = Buffer.from(hex, 'hex');
      // If MSB is 1, prefix with 0x00 for positive ASN.1 integer
      if (buf[0]! & 0x80) {
        buf = Buffer.concat([Buffer.from([0x00]), buf]);
      }
      return Buffer.concat([Buffer.from([0x02, buf.length]), buf]);
    };

    const rEncoded = encodeInt(rBig);
    const sEncoded = encodeInt(sBig);
    const totalLen = rEncoded.length + sEncoded.length;
    return Buffer.concat([Buffer.from([0x30, totalLen]), rEncoded, sEncoded]);
  }

  it('converts valid standard DER signature to canonical 65-byte EVM signature', async () => {
    // Generate valid signature using secp256k1
    const privBytes = Buffer.from(privKey.slice(2), 'hex');
    const sig = secp256k1.sign(Buffer.from(testDigest.slice(2), 'hex'), privBytes);
    const derSig = encodeDer(sig.r, sig.s);

    const parsed = parseKmsDerSignature({
      derSignature: derSig,
      digest: testDigest,
      expectedAddressOrPublicKey: expectedAddress,
    });

    expect(parsed.r).toBe(`0x${sig.r.toString(16).padStart(64, '0')}`);
    expect(parsed.v).toBeGreaterThanOrEqual(27);
    expect(parsed.v).toBeLessThanOrEqual(28);
    expect(parsed.signatureHex).toHaveLength(132); // '0x' + 65 bytes * 2
    expect(parsed.recoveredAddress.toLowerCase()).toBe(expectedAddress.toLowerCase());
  });

  it('normalizes high-s signature to canonical low-s (BIP-62 / EIP-2)', async () => {
    const privBytes = Buffer.from(privKey.slice(2), 'hex');
    const sig = secp256k1.sign(Buffer.from(testDigest.slice(2), 'hex'), privBytes);

    // Intentionally construct high-s counterpart: s_high = n - s_low
    const sLow = sig.s > SECP256K1_HALF_N ? SECP256K1_N - sig.s : sig.s;
    const sHigh = SECP256K1_N - sLow;
    const highSDer = encodeDer(sig.r, sHigh);

    const parsed = parseKmsDerSignature({
      derSignature: highSDer,
      digest: testDigest,
      expectedAddressOrPublicKey: expectedAddress,
    });

    expect(parsed.isNormalizedLowS).toBe(true);
    expect(BigInt(parsed.s)).toBe(sLow);
    expect(parsed.recoveredAddress.toLowerCase()).toBe(expectedAddress.toLowerCase());
  });

  it('recovers correct v and address from uncompressed 65-byte KMS public key', () => {
    const privBytes = Buffer.from(privKey.slice(2), 'hex');
    const pubKey65 = Buffer.from(secp256k1.getPublicKey(privBytes, false)); // Uncompressed 65 bytes

    const sig = secp256k1.sign(Buffer.from(testDigest.slice(2), 'hex'), privBytes);
    const derSig = encodeDer(sig.r, sig.s);

    const parsed = parseKmsDerSignature({
      derSignature: derSig,
      digest: testDigest,
      expectedAddressOrPublicKey: pubKey65,
    });

    expect(parsed.recoveredAddress.toLowerCase()).toBe(expectedAddress.toLowerCase());
  });

  it('recovers correct v and address from compressed 33-byte KMS public key', () => {
    const privBytes = Buffer.from(privKey.slice(2), 'hex');
    const pubKey33 = Buffer.from(secp256k1.getPublicKey(privBytes, true)); // Compressed 33 bytes

    const sig = secp256k1.sign(Buffer.from(testDigest.slice(2), 'hex'), privBytes);
    const derSig = encodeDer(sig.r, sig.s);

    const parsed = parseKmsDerSignature({
      derSignature: derSig,
      digest: testDigest,
      expectedAddressOrPublicKey: pubKey33,
    });

    expect(parsed.recoveredAddress.toLowerCase()).toBe(expectedAddress.toLowerCase());
  });

  it('rejects malformed DER without 0x30 SEQUENCE header', () => {
    const invalidDer = Buffer.from([0x02, 0x04, 0x01, 0x02, 0x03, 0x04]);
    expect(() =>
      parseKmsDerSignature({
        derSignature: invalidDer,
        digest: testDigest,
        expectedAddressOrPublicKey: expectedAddress,
      })
    ).toThrowError(/missing 0x30 SEQUENCE header/);
  });

  it('rejects zero or out-of-range scalars (r=0 or s=0)', () => {
    const zeroRDer = encodeDer(0n, 12345n);
    expect(() =>
      parseKmsDerSignature({
        derSignature: zeroRDer,
        digest: testDigest,
        expectedAddressOrPublicKey: expectedAddress,
      })
    ).toThrowError(/outside valid secp256k1 curve order/);

    const zeroSDer = encodeDer(12345n, 0n);
    expect(() =>
      parseKmsDerSignature({
        derSignature: zeroSDer,
        digest: testDigest,
        expectedAddressOrPublicKey: expectedAddress,
      })
    ).toThrowError(/outside valid secp256k1 curve order/);
  });

  it('rejects signature when tested against wrong public key / customer address (Fail-Closed)', () => {
    const privBytes = Buffer.from(privKey.slice(2), 'hex');
    const sig = secp256k1.sign(Buffer.from(testDigest.slice(2), 'hex'), privBytes);
    const derSig = encodeDer(sig.r, sig.s);

    const wrongAddress = '0x1111111111111111111111111111111111111111' as `0x${string}`;

    expect(() =>
      parseKmsDerSignature({
        derSignature: derSig,
        digest: testDigest,
        expectedAddressOrPublicKey: wrongAddress,
      })
    ).toThrowError(/KMS signature public key recovery failed/);
  });
});
