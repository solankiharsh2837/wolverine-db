import crypto from 'node:crypto';
import {
  TrustCommitment,
  ValidatorAttestation,
  QuorumCertificate,
} from '../trust_network/types.js';
import { computeQuorumCertificateDigest } from '../trust_network/consensus.js';
import { computeAttestationDigest } from '../trust_network/validator.js';
import { PersistentTrustLedger } from './persistent_ledger.js';
import { SlashingEvidenceRecord } from './types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export class BftConsensusEngine {
  private ledger: PersistentTrustLedger;
  public readonly totalValidators: number;
  public readonly requiredQuorum: number;
  public readonly maxByzantineFaults: number;

  private registeredValidators = new Map<string, Buffer>();
  private slashingRecords: SlashingEvidenceRecord[] = [];

  constructor(
    ledger: PersistentTrustLedger,
    totalValidators: number = 5,
    requiredQuorum?: number
  ) {
    this.ledger = ledger;
    this.totalValidators = totalValidators;
    this.maxByzantineFaults = Math.floor((totalValidators - 1) / 3); // f = 1 for N=5
    this.requiredQuorum = requiredQuorum ?? (totalValidators - this.maxByzantineFaults); // M = 4 for N=5
  }

  public registerValidatorKey(validatorId: string, publicKey: Buffer): void {
    this.registeredValidators.set(validatorId, publicKey);
  }

  public async processAttestations(
    commitment: TrustCommitment,
    attestations: ValidatorAttestation[]
  ): Promise<QuorumCertificate> {
    const validAttestations: ValidatorAttestation[] = [];
    const seenValidators = new Set<string>();

    for (const att of attestations) {
      // 1. Must be a registered validator
      const pubKey = this.registeredValidators.get(att.validatorId);
      if (!pubKey) continue;

      // 2. Reject duplicate signatures from same validator
      if (seenValidators.has(att.validatorId)) {
        continue;
      }

      // 3. Observed commitment digest must strictly match
      if (Buffer.compare(att.observedCommitmentDigest, commitment.commitmentDigest) !== 0) {
        // Byzantine Double Signing Detected!
        this.slashingRecords.push({
          evidenceId: crypto.randomUUID(),
          offendingValidatorId: att.validatorId,
          tenantId: commitment.tenantId,
          databaseId: commitment.databaseId,
          commitSeq: commitment.commitSeq.toString(),
          conflictingDigestHex1: commitment.commitmentDigest.toString('hex'),
          conflictingDigestHex2: att.observedCommitmentDigest.toString('hex'),
          detectedAtUs: (BigInt(Date.now()) * 1000n).toString(),
          proofType: 'DOUBLE_SIGNING',
        });
        continue;
      }

      // 4. Verify Cryptographic Signature
      const attDigest = computeAttestationDigest(
        commitment.commitmentId,
        att.validatorId,
        att.observedCommitmentDigest,
        att.timestampUs
      );

      try {
        const pubKeyObject = crypto.createPublicKey({
          key: Buffer.concat([
            Buffer.from('302a300506032b6570032100', 'hex'),
            pubKey,
          ]),
          format: 'der',
          type: 'spki',
        });

        if (crypto.verify(null, attDigest, pubKeyObject, att.signature)) {
          seenValidators.add(att.validatorId);
          validAttestations.push(att);
        }
      } catch {
        // Invalid signature discarded
      }
    }

    // 5. Enforce BFT Quorum Threshold
    if (validAttestations.length < this.requiredQuorum) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_UNAVAILABLE,
        `BFT_CONSENSUS_UNAVAILABLE: Reached ${validAttestations.length}/${this.requiredQuorum} required validator attestations (N=${this.totalValidators}, f=${this.maxByzantineFaults})`
      );
    }

    // 6. Assemble Quorum Certificate
    const finalizedAtUs = BigInt(Date.now()) * 1000n;
    const certificateDigest = computeQuorumCertificateDigest(
      commitment.commitmentId,
      commitment.commitmentDigest.toString('hex'),
      commitment.validatorSetId,
      commitment.epoch,
      validAttestations.length,
      this.totalValidators,
      finalizedAtUs
    );

    const certificate: QuorumCertificate = {
      commitmentId: commitment.commitmentId,
      commitmentDigest: commitment.commitmentDigest,
      validatorSetId: commitment.validatorSetId,
      epoch: commitment.epoch,
      quorumCount: validAttestations.length,
      totalValidators: this.totalValidators,
      finalizedAtUs,
      attestations: validAttestations,
      certificateDigest,
      finalityStatus: 'FINALIZED',
    };

    // 7. Append FINALIZATION to Persistent Ledger
    await this.ledger.appendRecord(
      'FINALIZATION',
      {
        commitmentId: commitment.commitmentId,
        checkpointId: commitment.checkpointId,
        commitSeq: commitment.commitSeq.toString(),
        commitmentDigestHex: commitment.commitmentDigest.toString('hex'),
        certificateDigestHex: certificateDigest.toString('hex'),
        quorumCount: validAttestations.length,
        totalValidators: this.totalValidators,
        finalizedAtUs: finalizedAtUs.toString(),
      },
      commitment.epoch,
      commitment.validatorSetId,
      commitment.tenantId,
      commitment.databaseId
    );

    return certificate;
  }

  public getSlashingRecords(): SlashingEvidenceRecord[] {
    return [...this.slashingRecords];
  }
}
