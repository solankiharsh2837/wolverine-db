import { TrustCommitment } from '../trust_network/types.js';
import { TrustServiceStatus, TrustSlaStatus, DurabilityState } from './types.js';

export class CustomerDisasterSlaManager {
  private localQueue: TrustCommitment[] = [];
  private lastFinalizedDatabaseSeq: bigint = 0n;
  private latestObservedDatabaseSeq: bigint = 0n;
  private lastFinalizedTrustSeq: bigint = 0n;
  private currentEpoch: number = 1;
  private isWolverineOnline: boolean = true;
  private ledgerHealth: DurabilityState = 'HEALTHY';
  private validatorQuorum: string = '5/5';

  public queueCommitment(commitment: TrustCommitment): void {
    this.latestObservedDatabaseSeq = commitment.commitSeq;
    this.localQueue.push(commitment);
  }

  public recordFinalized(databaseSeq: bigint, trustSeq: bigint): void {
    this.lastFinalizedDatabaseSeq = databaseSeq;
    this.lastFinalizedTrustSeq = trustSeq;
    this.localQueue = this.localQueue.filter((c) => c.commitSeq > databaseSeq);
  }

  public setWolverineOnline(isOnline: boolean, ledgerHealth?: DurabilityState): void {
    this.isWolverineOnline = isOnline;
    if (ledgerHealth) {
      this.ledgerHealth = ledgerHealth;
    }
  }

  public getQueuedCommitments(): TrustCommitment[] {
    return [...this.localQueue];
  }

  public getStatus(): TrustServiceStatus {
    let trustStatus: TrustSlaStatus = 'TRUST_CURRENT';

    if (!this.isWolverineOnline) {
      trustStatus = 'TRUST_OUTAGE';
    } else if (this.localQueue.length > 0) {
      trustStatus = 'TRUST_PENDING';
    } else if (this.ledgerHealth !== 'HEALTHY') {
      trustStatus = 'TRUST_DEGRADED';
    }

    return {
      trustStatus,
      lastFinalizedDatabaseSeq: this.lastFinalizedDatabaseSeq,
      latestObservedDatabaseSeq: this.latestObservedDatabaseSeq,
      pendingCommitments: this.localQueue.length,
      lastFinalizedTrustSeq: this.lastFinalizedTrustSeq,
      currentEpoch: this.currentEpoch,
      validatorQuorum: this.validatorQuorum,
      ledgerHealth: this.ledgerHealth,
    };
  }
}
