import crypto from 'node:crypto';
import {
  TrustCommitment,
  ValidatorAttestation,
  QuorumCertificate,
  TrustLedgerRecord,
} from './types.js';
import { WolverineTrustLedger } from './ledger.js';
import { computeAttestationDigest } from './validator.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export function computeQuorumCertificateDigest(
  commitmentId: string,
  commitmentDigestHex: string,
  validatorSetId: string,
  epoch: number,
  quorumCount: number,
  totalValidators: number,
  finalizedAtUs: bigint
): Buffer {
  const domain = Buffer.from('WDB:QUORUM_CERT:v1:', 'utf8');

  const canonicalPayload = canonicalizeJson({
    commitmentId,
    commitmentDigestHex,
    validatorSetId,
    epoch,
    quorumCount,
    totalValidators,
    finalizedAtUs: finalizedAtUs.toString(),
  });

  return crypto
    .createHash('sha256')
    .update(Buffer.concat([domain, Buffer.from(canonicalPayload, 'utf8')]))
    .digest();
}

export class TrustConsensusEngine {
  private ledger: WolverineTrustLedger;
  private requiredQuorum: number;
  private totalValidators: number;
  private validatorPublicKeys = new Map<string, Buffer>();

  constructor(
    ledger: WolverineTrustLedger,
    requiredQuorum: number = 3,
    totalValidators: number = 5
  ) {
    this.ledger = ledger;
    this.requiredQuorum = requiredQuorum;
    this.totalValidators = totalValidators;
  }

  public registerValidatorKey(validatorId: string, publicKey: Buffer): void {
    this.validatorPublicKeys.set(validatorId, publicKey);
  }

  public processAttestationsWithRecord(
    commitment: TrustCommitment,
    attestations: ValidatorAttestation[]
  ): { certificate: QuorumCertificate; ledgerRecord: TrustLedgerRecord } {
    // 1. Filter and verify valid attestations
    const validAttestations: ValidatorAttestation[] = [];
    const seenValidators = new Set<string>();

    for (const att of attestations) {
      if (seenValidators.has(att.validatorId)) continue;
      seenValidators.add(att.validatorId);

      // Check observed digest matches commitment
      if (!timingSafeEqualHashes(att.observedCommitmentDigest, commitment.commitmentDigest)) {
        continue;
      }

      // Verify validator signature
      const pubKey = this.validatorPublicKeys.get(att.validatorId);
      if (!pubKey) continue;

      const attDigest = computeAttestationDigest(
        att.commitmentId,
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
          validAttestations.push(att);
        }
      } catch {
        // Invalid signature ignored
      }
    }

    // 2. Check Quorum Threshold
    if (validAttestations.length < this.requiredQuorum) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_UNAVAILABLE,
        `CONSENSUS_UNAVAILABLE: Reached ${validAttestations.length}/${this.requiredQuorum} required validator attestations`
      );
    }

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
      attestations: validAttestations,
      quorumCount: validAttestations.length,
      totalValidators: this.totalValidators,
      finalityStatus: 'FINALIZED',
      finalizedAtUs,
      certificateDigest,
    };

    // 3. Append FINALIZATION to Trust Ledger
    const ledgerRecord = this.ledger.appendRecord(
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

    return { certificate, ledgerRecord };
  }

  public processAttestations(
    commitment: TrustCommitment,
    attestations: ValidatorAttestation[]
  ): QuorumCertificate {
    return this.processAttestationsWithRecord(commitment, attestations).certificate;
  }
}
