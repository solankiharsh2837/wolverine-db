import { RiskScoreBreakdown, ResponseLevel } from './types.js';

export interface RiskInputSignals {
  stateIntegrity: { score: number; evidence: string }; // 0..100
  provenance: { score: number; evidence: string };     // 0..100
  behavioral: { score: number; evidence: string };     // 0..100
  historical: { score: number; evidence: string };     // 0..100
  externalIntel: { score: number; evidence: string };  // 0..100
}

export class DistributedRiskEngine {
  public static readonly WEIGHTS = {
    stateIntegrity: 0.35,
    provenance: 0.20,
    behavioral: 0.20,
    historical: 0.10,
    externalIntel: 0.15,
  };

  /**
   * Calculates an itemized, explainable composite risk score across the 5 signal vectors.
   */
  public static evaluateRisk(signals: RiskInputSignals): RiskScoreBreakdown {
    const cState = signals.stateIntegrity.score * this.WEIGHTS.stateIntegrity;
    const cProv = signals.provenance.score * this.WEIGHTS.provenance;
    const cBeh = signals.behavioral.score * this.WEIGHTS.behavioral;
    const cHist = signals.historical.score * this.WEIGHTS.historical;
    const cExt = signals.externalIntel.score * this.WEIGHTS.externalIntel;

    const rawComposite = cState + cProv + cBeh + cHist + cExt;
    const compositeScore = Math.min(100, Math.round(rawComposite));

    let severity: RiskScoreBreakdown['severity'] = 'LOW';
    if (compositeScore >= 80) severity = 'CRITICAL';
    else if (compositeScore >= 60) severity = 'HIGH';
    else if (compositeScore >= 40) severity = 'MEDIUM';

    return {
      compositeScore,
      severity,
      factors: {
        stateIntegrity: {
          score: signals.stateIntegrity.score,
          contribution: Number(cState.toFixed(2)),
          evidence: signals.stateIntegrity.evidence,
        },
        provenance: {
          score: signals.provenance.score,
          contribution: Number(cProv.toFixed(2)),
          evidence: signals.provenance.evidence,
        },
        behavioral: {
          score: signals.behavioral.score,
          contribution: Number(cBeh.toFixed(2)),
          evidence: signals.behavioral.evidence,
        },
        historical: {
          score: signals.historical.score,
          contribution: Number(cHist.toFixed(2)),
          evidence: signals.historical.evidence,
        },
        externalIntel: {
          score: signals.externalIntel.score,
          contribution: Number(cExt.toFixed(2)),
          evidence: signals.externalIntel.evidence,
        },
      },
    };
  }

  /**
   * Maps composite risk score to coordinated response level (WDB-0044).
   */
  public static mapResponseLevel(score: number): ResponseLevel {
    if (score >= 90) return 'LEVEL_5_CRITICAL_DEFENSE';
    if (score >= 70) return 'LEVEL_4_REQUIRE_APPROVAL';
    if (score >= 50) return 'LEVEL_3_PROPOSE';
    if (score >= 30) return 'LEVEL_2_FLAG';
    return 'LEVEL_1_OBSERVE';
  }
}
