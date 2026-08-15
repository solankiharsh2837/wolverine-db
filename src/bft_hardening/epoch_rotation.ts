import { EpochTransitionRecord } from './types.js';
import { PersistentTrustLedger } from '../trust_service/persistent_ledger.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export class EpochRotationManager {
  private currentEpoch: number = 1;
  private currentValidatorSetId: string = 'valset-prod-v1';
  private ledger: PersistentTrustLedger;

  constructor(ledger: PersistentTrustLedger, initialEpoch: number = 1) {
    this.ledger = ledger;
    this.currentEpoch = initialEpoch;
  }

  public getCurrentEpoch(): number {
    return this.currentEpoch;
  }

  public getCurrentValidatorSetId(): string {
    return this.currentValidatorSetId;
  }

  public async advanceEpoch(newValidatorSetId?: string): Promise<EpochTransitionRecord> {
    const oldEpoch = this.currentEpoch;
    this.currentEpoch += 1;
    if (newValidatorSetId) {
      this.currentValidatorSetId = newValidatorSetId;
    }

    const snapshot = this.ledger.getStateRootSnapshot();
    const timestampUs = BigInt(Date.now()) * 1000n;

    const transition: EpochTransitionRecord = {
      oldEpoch,
      newEpoch: this.currentEpoch,
      transitionTimestampUs: timestampUs,
      previousEpochHeadDigest: snapshot.chainHeadDigest,
      activeValidatorSetId: this.currentValidatorSetId,
    };

    // Commit EPOCH_CHANGE to ledger
    await this.ledger.appendRecord(
      'EPOCH_CHANGE',
      {
        oldEpoch,
        newEpoch: this.currentEpoch,
        activeValidatorSetId: this.currentValidatorSetId,
        previousEpochHeadDigestHex: snapshot.chainHeadDigest.toString('hex'),
      },
      this.currentEpoch,
      this.currentValidatorSetId
    );

    return transition;
  }

  public validateCommitmentEpoch(commitmentEpoch: number): boolean {
    // Grace period: allow current epoch or currentEpoch - 1
    if (commitmentEpoch < this.currentEpoch - 1) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_UNAVAILABLE,
        `STALE_EPOCH: Commitment epoch ${commitmentEpoch} is expired (current network epoch: ${this.currentEpoch})`
      );
    }
    return true;
  }
}
