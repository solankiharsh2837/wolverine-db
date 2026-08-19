import crypto from 'node:crypto';
import { CustomerKeyRotationRecord } from './types.js';
import { PersistentTrustLedger } from '../trust_service/persistent_ledger.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import { encodeProtocolTuple } from '../crypto/canonical.js';

export function computeKeyRotationPayload(
  tenantId: string,
  databaseId: string,
  rotationSeq: bigint,
  oldPubkey: Buffer,
  newPubkey: Buffer
): Buffer {
  return encodeProtocolTuple('WDB:KEY_ROTATION:v2:', [
    tenantId,
    databaseId,
    BigInt(rotationSeq),
    oldPubkey,
    newPubkey,
  ]);
}

function verifyEd25519Signature(publicKey: Buffer, payload: Buffer, signature: Buffer): boolean {
  const spkiBuffer = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    publicKey,
  ]);

  try {
    const keyObject = crypto.createPublicKey({
      key: spkiBuffer,
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, payload, keyObject, signature);
  } catch {
    return false;
  }
}

export class CustomerKeyRotationManager {
  private ledger: PersistentTrustLedger;
  private activeKeys = new Map<string, Buffer>();
  private lastRotationSeqs = new Map<string, bigint>();

  constructor(ledger: PersistentTrustLedger) {
    this.ledger = ledger;
  }

  public registerGenesisKey(tenantId: string, pubkey: Buffer): void {
    this.registerInitialKey(tenantId, pubkey);
  }

  public registerInitialKey(tenantId: string, pubkey: Buffer): void {
    this.activeKeys.set(tenantId, pubkey);
  }

  public getActiveKey(tenantId: string): Buffer | undefined {
    return this.activeKeys.get(tenantId);
  }

  public verifyRotationProof(
    record: CustomerKeyRotationRecord,
    oldPub: Buffer,
    newPub: Buffer
  ): boolean {
    const oldSig = Buffer.from(record.oldKeySignatureHex, 'hex');
    const newSig = Buffer.from(record.newKeySignatureHex, 'hex');

    const payload = computeKeyRotationPayload(
      record.tenantId,
      record.databaseId,
      record.rotationSeq,
      oldPub,
      newPub
    );

    const isOldValid = verifyEd25519Signature(oldPub, payload, oldSig);
    const isNewValid = verifyEd25519Signature(newPub, payload, newSig);

    return isOldValid && isNewValid;
  }

  /**
   * Statically verifies a dual-signed key rotation record.
   */
  public static verifyRotationRecord(record: CustomerKeyRotationRecord): boolean {
    const oldPub = Buffer.from(record.oldPubkeyHex, 'hex');
    const newPub = Buffer.from(record.newPubkeyHex, 'hex');
    const oldSig = Buffer.from(record.oldKeySignatureHex, 'hex');
    const newSig = Buffer.from(record.newKeySignatureHex, 'hex');

    const payload = computeKeyRotationPayload(
      record.tenantId,
      record.databaseId,
      record.rotationSeq,
      oldPub,
      newPub
    );

    const isOldValid = verifyEd25519Signature(oldPub, payload, oldSig);
    const isNewValid = verifyEd25519Signature(newPub, payload, newSig);

    return isOldValid && isNewValid;
  }

  public async executeKeyRotation(
    tenantId: string,
    databaseId: string,
    oldPrivateKey: crypto.KeyObject,
    oldPubkey: Buffer,
    newPrivateKey: crypto.KeyObject,
    newPubkey: Buffer,
    rotationSeq: bigint
  ): Promise<CustomerKeyRotationRecord> {
    // 0. Enforce Monotonic Rotation Sequence
    const prevSeq = this.lastRotationSeqs.get(tenantId) ?? 0n;
    if (rotationSeq <= prevSeq) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Key rotation failed: Non-monotonic rotationSeq ${rotationSeq} <= ${prevSeq} for tenant ${tenantId}`
      );
    }

    // 1. Verify Active Key Registration
    const currentActive = this.activeKeys.get(tenantId);
    if (!currentActive || Buffer.compare(currentActive, oldPubkey) !== 0) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Key rotation failed: Provided old public key does not match active registered key for tenant ${tenantId}`
      );
    }

    // 2. Cryptographic Keypair Correspondence Verification
    try {
      const derivedOldPub = crypto
        .createPublicKey(oldPrivateKey)
        .export({ type: 'spki', format: 'der' })
        .subarray(-32);

      if (Buffer.compare(derivedOldPub, oldPubkey) !== 0) {
        throw new WolverineError(
          WolverineErrorCode.UNAUTHORIZED_MUTATION,
          'Key rotation failed: oldPrivateKey does not match oldPubkey'
        );
      }

      const derivedNewPub = crypto
        .createPublicKey(newPrivateKey)
        .export({ type: 'spki', format: 'der' })
        .subarray(-32);

      if (Buffer.compare(derivedNewPub, newPubkey) !== 0) {
        throw new WolverineError(
          WolverineErrorCode.UNAUTHORIZED_MUTATION,
          'Key rotation failed: newPrivateKey does not match newPubkey'
        );
      }
    } catch (err: any) {
      if (err instanceof WolverineError) throw err;
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Keypair verification failed: ${err.message}`
      );
    }

    // 3. Compute Canonical Signing Payload
    const timestampUs = BigInt(Date.now()) * 1000n;
    const rotationPayload = computeKeyRotationPayload(
      tenantId,
      databaseId,
      rotationSeq,
      oldPubkey,
      newPubkey
    );

    // 4. Dual Signatures
    const oldSig = crypto.sign(null, rotationPayload, oldPrivateKey);
    const newSig = crypto.sign(null, rotationPayload, newPrivateKey);

    // 5. Enforce Verification of Both Signatures Before Accepting
    if (!verifyEd25519Signature(oldPubkey, rotationPayload, oldSig)) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
        'Key rotation rejected: Invalid signature produced by old customer key'
      );
    }

    if (!verifyEd25519Signature(newPubkey, rotationPayload, newSig)) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
        'Key rotation rejected: Invalid signature produced by new customer key'
      );
    }

    const record: CustomerKeyRotationRecord = {
      tenantId,
      databaseId,
      oldPubkeyHex: oldPubkey.toString('hex'),
      newPubkeyHex: newPubkey.toString('hex'),
      rotationSeq,
      oldKeySignatureHex: oldSig.toString('hex'),
      newKeySignatureHex: newSig.toString('hex'),
      timestampUs,
    };

    // Retrieve active epoch and validator set ID from ledger
    const ledgerRecords = this.ledger.getRecords();
    const lastRecord = ledgerRecords[ledgerRecords.length - 1];
    const activeEpoch = lastRecord ? lastRecord.epoch : 1;
    const activeValsetId = lastRecord ? lastRecord.validatorSetId : 'valset-prod-v1';

    // 6. Commit key rotation record to persistent ledger
    await this.ledger.appendRecord(
      'REVOCATION',
      {
        action: 'KEY_ROTATION',
        tenantId,
        databaseId,
        oldPubkeyHex: record.oldPubkeyHex,
        newPubkeyHex: record.newPubkeyHex,
        rotationSeq: rotationSeq.toString(),
        oldKeySignatureHex: record.oldKeySignatureHex,
        newKeySignatureHex: record.newKeySignatureHex,
      },
      activeEpoch,
      activeValsetId,
      tenantId,
      databaseId
    );

    // 7. Update active key and monotonic sequence in memory
    this.activeKeys.set(tenantId, newPubkey);
    this.lastRotationSeqs.set(tenantId, rotationSeq);

    return record;
  }
}
