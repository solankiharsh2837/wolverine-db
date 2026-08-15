import { TrustTimeRecord } from './types.js';
import { PortableTrustProof } from '../trust_network/types.js';

export class TrustTimeManager {
  private timelineRecords = new Map<string, TrustTimeRecord>();

  public registerProof(proof: PortableTrustProof): TrustTimeRecord {
    const key = `${proof.tenantId}:${proof.databaseId}:${proof.commitment.commitSeq}`;
    const record: TrustTimeRecord = {
      databaseId: proof.databaseId,
      commitSeq: BigInt(proof.commitment.commitSeq),
      checkpointId: proof.commitment.checkpointId,
      checkpointDigestHex: proof.commitment.checkpointDigestHex,
      ledgerSeq: BigInt(proof.ledgerRecord.ledgerSeq),
      epoch: proof.quorumCertificate.epoch,
      finalizedAtUs: BigInt(proof.quorumCertificate.finalizedAtUs),
      quorumDigestHex: proof.quorumCertificate.certificateDigestHex,
    };

    this.timelineRecords.set(key, record);
    return record;
  }

  public getTrustTime(
    tenantId: string,
    databaseId: string,
    commitSeq: bigint
  ): TrustTimeRecord | null {
    return this.timelineRecords.get(`${tenantId}:${databaseId}:${commitSeq}`) || null;
  }

  /**
   * Verifies that database commitSeq existed at or prior to the specified target ledger sequence.
   */
  public verifyTemporalOrdering(
    tenantId: string,
    databaseId: string,
    commitSeq: bigint,
    targetLedgerSeq: bigint
  ): {
    isPrecedent: boolean;
    actualLedgerSeq?: bigint | undefined;
    epoch?: number | undefined;
  } {
    const record = this.getTrustTime(tenantId, databaseId, commitSeq);
    if (!record) {
      return { isPrecedent: false };
    }

    return {
      isPrecedent: record.ledgerSeq <= targetLedgerSeq,
      actualLedgerSeq: record.ledgerSeq,
      epoch: record.epoch,
    };
  }
}
