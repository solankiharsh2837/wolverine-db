export interface ChaosProbabilities {
  dropRate: number; // 0.0 to 1.0
  duplicateRate: number;
  delayRate: number;
  corruptRate: number;
}

export interface ChaosRunMetrics {
  totalRpcs: number;
  droppedRpcs: number;
  duplicatedRpcs: number;
  delayedRpcs: number;
  corruptedRpcs: number;
  validQCs: number;
  falseFinalityEvents: number;
}

export class ProbabilisticNetworkChaosHarness {
  private rates: ChaosProbabilities;
  private metrics: ChaosRunMetrics = {
    totalRpcs: 0,
    droppedRpcs: 0,
    duplicatedRpcs: 0,
    delayedRpcs: 0,
    corruptedRpcs: 0,
    validQCs: 0,
    falseFinalityEvents: 0,
  };

  constructor(rates: Partial<ChaosProbabilities> = {}) {
    this.rates = {
      dropRate: rates.dropRate ?? 0.1,
      duplicateRate: rates.duplicateRate ?? 0.1,
      delayRate: rates.delayRate ?? 0.1,
      corruptRate: rates.corruptRate ?? 0.05,
    };
  }

  public shouldDrop(): boolean {
    this.metrics.totalRpcs++;
    const drop = Math.random() < this.rates.dropRate;
    if (drop) this.metrics.droppedRpcs++;
    return drop;
  }

  public shouldDuplicate(): boolean {
    const dupe = Math.random() < this.rates.duplicateRate;
    if (dupe) this.metrics.duplicatedRpcs++;
    return dupe;
  }

  public async applyDelay(): Promise<boolean> {
    const delay = Math.random() < this.rates.delayRate;
    if (delay) {
      this.metrics.delayedRpcs++;
      await new Promise((r) => setTimeout(r, Math.floor(Math.random() * 50) + 10));
    }
    return delay;
  }

  public shouldCorrupt(): boolean {
    const corrupt = Math.random() < this.rates.corruptRate;
    if (corrupt) this.metrics.corruptedRpcs++;
    return corrupt;
  }

  public recordSuccess(): void {
    this.metrics.validQCs++;
  }

  public recordFalseFinality(): void {
    this.metrics.falseFinalityEvents++;
  }

  public getMetrics(): ChaosRunMetrics {
    return { ...this.metrics };
  }
}
