export interface TrustCommitmentRecord {
  commitmentId: string;
  tenantId: string;
  databaseId: string;
  checkpointId: string;
  checkpointDigest: Buffer; // 32 bytes SHA-256
  commitSeq: bigint;
  anchoredEpochUs: bigint;
  ledgerProof: string;
}

export interface IWolverineTrustService {
  anchorCheckpoint(
    tenantId: string,
    databaseId: string,
    checkpointId: string,
    checkpointDigest: Buffer,
    commitSeq: bigint
  ): Promise<TrustCommitmentRecord>;

  getCommitment(checkpointId: string): Promise<TrustCommitmentRecord | null>;

  verifyCommitment(checkpointId: string, expectedDigest: Buffer): Promise<boolean>;
}
