import { IWolverineTrustService, TrustCommitmentRecord } from './types.js';

export class WolverineLegacyEvidenceAgent {
  private trustService: IWolverineTrustService;
  private tenantId: string;
  private databaseId: string;

  constructor(trustService: IWolverineTrustService, tenantId: string, databaseId: string) {
    this.trustService = trustService;
    this.tenantId = tenantId;
    this.databaseId = databaseId;
  }

  public async forwardCheckpointCommitment(
    checkpointId: string,
    checkpointDigest: Buffer,
    commitSeq: bigint
  ): Promise<TrustCommitmentRecord> {
    return this.trustService.anchorCheckpoint(
      this.tenantId,
      this.databaseId,
      checkpointId,
      checkpointDigest,
      commitSeq
    );
  }

  public async verifyCheckpointWithTrustLedger(
    checkpointId: string,
    expectedDigest: Buffer
  ): Promise<boolean> {
    return this.trustService.verifyCommitment(checkpointId, expectedDigest);
  }
}
