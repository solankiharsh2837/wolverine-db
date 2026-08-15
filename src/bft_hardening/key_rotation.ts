import crypto from 'node:crypto';
import { CustomerKeyRotationRecord } from './types.js';
import { PersistentTrustLedger } from '../trust_service/persistent_ledger.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export class CustomerKeyRotationManager {
  private activeKeys = new Map<string, Buffer>(); // tenantId -> currentPubkey
  private ledger: PersistentTrustLedger;

  constructor(ledger: PersistentTrustLedger) {
    this.ledger = ledger;
  }

  public registerInitialKey(tenantId: string, pubkey: Buffer): void {
    this.activeKeys.set(tenantId, pubkey);
  }

  public getActiveKey(tenantId: string): Buffer | null {
    return this.activeKeys.get(tenantId) || null;
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
    const currentActive = this.activeKeys.get(tenantId);
    if (!currentActive || Buffer.compare(currentActive, oldPubkey) !== 0) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Key rotation failed: Provided old public key does not match active registered key for tenant ${tenantId}`
      );
    }

    const timestampUs = BigInt(Date.now()) * 1000n;
    const rotationPayload = Buffer.concat([
      Buffer.from('WDB:KEY_ROTATION:v1:', 'utf8'),
      Buffer.from(tenantId, 'utf8'),
      oldPubkey,
      newPubkey,
    ]);

    const oldSig = crypto.sign(null, rotationPayload, oldPrivateKey);
    const newSig = crypto.sign(null, rotationPayload, newPrivateKey);

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

    // Commit key rotation record to persistent ledger
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
      1,
      'valset-prod-v1',
      tenantId,
      databaseId
    );

    // Update active key in memory
    this.activeKeys.set(tenantId, newPubkey);

    return record;
  }
}
