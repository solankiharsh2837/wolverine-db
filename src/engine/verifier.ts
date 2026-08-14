import { decodeBinaryRecord } from '../binary/decoder.js';
import { computeChangeHash, computeVersionHash, timingSafeEqualHashes, GENESIS_PREDECEASED_HASH } from '../crypto/hash.js';
import { MerkleTree } from '../crypto/merkle.js';

export interface IntegrityVerificationReport {
  status: 'VALID' | 'CHANGE_HASH_MISMATCH' | 'VERSION_HASH_MISMATCH' | 'MERKLE_ROOT_MISMATCH' | 'MALFORMED_RECORD' | 'INDETERMINATE';
  checkedRecordsCount: number;
  firstFailureSeq?: number;
  failureMessage?: string;
  verifiedScope: string;
}

export interface StoredChangeRecord {
  changeSeq: number;
  changeHash: Buffer;
  previousHash: Buffer;
  recordBytes: Buffer;
}

export interface StoredVersionRecord {
  versionId: string;
  parentVersionId: string;
  versionHash: Buffer;
  versionBytes: Buffer;
  parentVersionHash: Buffer;
  stateRoot: Buffer;
}

export interface StoredCheckpointRecord {
  checkpointId: string;
  protectedScope: string;
  versionId: string;
  leafCount: number;
  merkleRoot: Buffer;
}

/**
 * Verifies change hash chain integrity.
 */
export function verifyChangeHashChain(
  records: StoredChangeRecord[]
): IntegrityVerificationReport {
  if (!records || records.length === 0) {
    return {
      status: 'VALID',
      checkedRecordsCount: 0,
      verifiedScope: 'global',
    };
  }

  let expectedPrevHash: Buffer = GENESIS_PREDECEASED_HASH;

  for (let i = 0; i < records.length; i++) {
    const rec = records[i];

    // Decode canonical record to verify well-formedness
    try {
      decodeBinaryRecord(rec.recordBytes);
    } catch (err: any) {
      return {
        status: 'MALFORMED_RECORD',
        checkedRecordsCount: i,
        firstFailureSeq: rec.changeSeq,
        failureMessage: `Malformed binary record at seq ${rec.changeSeq}: ${err.message}`,
        verifiedScope: 'global',
      };
    }

    // Verify previous_hash link
    if (!timingSafeEqualHashes(rec.previousHash, expectedPrevHash)) {
      return {
        status: 'CHANGE_HASH_MISMATCH',
        checkedRecordsCount: i,
        firstFailureSeq: rec.changeSeq,
        failureMessage: `Predecessor hash mismatch at change_seq ${rec.changeSeq}`,
        verifiedScope: 'global',
      };
    }

    // Compute expected change hash
    const computedHash = computeChangeHash(rec.recordBytes, rec.previousHash);
    if (!timingSafeEqualHashes(computedHash, rec.changeHash)) {
      return {
        status: 'CHANGE_HASH_MISMATCH',
        checkedRecordsCount: i,
        firstFailureSeq: rec.changeSeq,
        failureMessage: `Computed change hash mismatch at change_seq ${rec.changeSeq}`,
        verifiedScope: 'global',
      };
    }

    expectedPrevHash = Buffer.from(rec.changeHash);
  }

  return {
    status: 'VALID',
    checkedRecordsCount: records.length,
    verifiedScope: 'global',
  };
}

/**
 * Verifies version graph parent links and version hash chain integrity.
 */
export function verifyVersionChain(
  versions: StoredVersionRecord[]
): IntegrityVerificationReport {
  let expectedParentHash: Buffer = GENESIS_PREDECEASED_HASH;

  for (let i = 0; i < versions.length; i++) {
    const ver = versions[i];
    const computedHash = computeVersionHash(ver.versionBytes, expectedParentHash);

    if (!timingSafeEqualHashes(computedHash, ver.versionHash)) {
      return {
        status: 'VERSION_HASH_MISMATCH',
        checkedRecordsCount: i,
        failureMessage: `Version hash mismatch for version ${ver.versionId}`,
        verifiedScope: 'versions',
      };
    }

    expectedParentHash = Buffer.from(ver.versionHash);
  }

  return {
    status: 'VALID',
    checkedRecordsCount: versions.length,
    verifiedScope: 'versions',
  };
}

/**
 * Verifies state leaves against a recorded Merkle checkpoint.
 */
export function verifyMerkleCheckpoint(
  leafPayloads: Buffer[],
  checkpoint: StoredCheckpointRecord
): IntegrityVerificationReport {
  const tree = new MerkleTree(leafPayloads);

  if (!timingSafeEqualHashes(tree.root, checkpoint.merkleRoot)) {
    return {
      status: 'MERKLE_ROOT_MISMATCH',
      checkedRecordsCount: leafPayloads.length,
      failureMessage: `Merkle root mismatch for scope "${checkpoint.protectedScope}". Expected 0x${checkpoint.merkleRoot.toString('hex')}, got 0x${tree.root.toString('hex')}`,
      verifiedScope: checkpoint.protectedScope,
    };
  }

  return {
    status: 'VALID',
    checkedRecordsCount: leafPayloads.length,
    verifiedScope: checkpoint.protectedScope,
  };
}
