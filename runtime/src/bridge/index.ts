import { IncidentEngine, IncidentReport } from '../incidents/index.js';

export interface WolverineDBVerificationReport {
  status: string;
  checkedRecordsCount: number;
  failureMessage?: string;
  firstFailureSeq?: number;
  verifiedScope: string;
}

export interface WolverineDBClient {
  verify(scope?: string): Promise<WolverineDBVerificationReport>;
}

export class WolverineDBBridge {
  private db: WolverineDBClient;

  constructor(db: WolverineDBClient) {
    this.db = db;
  }

  public async auditAndVerifyScope(scope: string): Promise<{
    verification: WolverineDBVerificationReport;
    incident?: IncidentReport;
  }> {
    const report = await this.db.verify(scope);

    if (report.status !== 'VALID') {
      const incident = IncidentEngine.createReport('CRITICAL', 'DATABASE_DIVERGENCE_DETECTED', {
        scope,
        verificationStatus: report.status,
        failureMessage: report.failureMessage,
        firstFailureSeq: report.firstFailureSeq,
      });

      return { verification: report, incident };
    }

    return { verification: report };
  }
}
