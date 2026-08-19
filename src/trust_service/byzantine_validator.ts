import crypto from 'node:crypto';
import {
  TrustCommitment,
  ValidatorAttestation,
} from '../trust_network/types.js';
import { verifyCustomerCommitment } from '../trust_network/commitment.js';
import { computeAttestationDigest } from '../trust_network/validator.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import { ByzantineValidatorConfig, SlashingEvidenceRecord } from './types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export class ByzantineTrustValidator {
  public readonly config: ByzantineValidatorConfig;
  public readonly publicKey: Buffer;
  private readonly privateKey: crypto.KeyObject;
  private attestationSeq: bigint = 0n;

  // Local persistent journal: key -> { commitSeq, commitmentId, checkpointDigest, attestation }
  private journal = new Map<
    string,
    {
      commitSeq: bigint;
      commitmentId: string;
      checkpointDigest: Buffer;
      attestation: ValidatorAttestation;
    }
  >();

  private slashingEvidence: SlashingEvidenceRecord[] = [];

  constructor(
    config: ByzantineValidatorConfig,
    keyPair?: { publicKey: Buffer; privateKey: crypto.KeyObject }
  ) {
    this.config = config;

    if (keyPair) {
      this.publicKey = keyPair.publicKey;
      this.privateKey = keyPair.privateKey;
    } else {
      const generated = crypto.generateKeyPairSync('ed25519');
      this.publicKey = generated.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
      this.privateKey = generated.privateKey;
    }
  }

  public attestCommitment(
    commitment: TrustCommitment,
    expectedCustomerPubkey?: Buffer
  ): ValidatorAttestation {
    // 1. Verify Customer Signature & Commitment Digest Binding
    const isCustomerValid = verifyCustomerCommitment(commitment, expectedCustomerPubkey);
    if (!isCustomerValid) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Byzantine Validator ${this.config.validatorId} rejected: Invalid customer signature or tenant binding`
      );
    }

    // 2. Journal & Equivocation Verification
    const journalKey = `${commitment.tenantId}:${commitment.databaseId}`;
    const prior = this.journal.get(journalKey);

    if (prior) {
      // Idempotent retry: Exact same seq, commitment ID, and checkpoint digest
      if (
        commitment.commitSeq === prior.commitSeq &&
        commitment.commitmentId === prior.commitmentId &&
        timingSafeEqualHashes(commitment.checkpointDigest, prior.checkpointDigest)
      ) {
        return prior.attestation;
      }

      // Conflict / Equivocation detected!
      if (commitment.commitSeq <= prior.commitSeq) {
        const evidence: SlashingEvidenceRecord = {
          evidenceId: crypto.randomUUID(),
          offendingGatewayId: 'gateway-rogue-attempt',
          tenantId: commitment.tenantId,
          databaseId: commitment.databaseId,
          commitSeq: commitment.commitSeq.toString(),
          conflictingDigestHex1: prior.checkpointDigest.toString('hex'),
          conflictingDigestHex2: commitment.checkpointDigest.toString('hex'),
          detectedAtUs: (BigInt(Date.now()) * 1000n).toString(),
          proofType: 'CONFLICTING_COMMITMENT',
        };
        this.slashingEvidence.push(evidence);

        throw new WolverineError(
          WolverineErrorCode.HISTORY_MUTATION_DETECTED,
          `CONFLICTING_COMMITMENT: Validator ${this.config.validatorId} detected conflicting digest for tenant ${commitment.tenantId} at sequence ${commitment.commitSeq}`
        );
      }
    }

    // 3. Increment sequence and issue attestation
    this.attestationSeq += 1n;
    const timestampUs = BigInt(Date.now()) * 1000n;

    const attestationDigest = computeAttestationDigest(
      commitment.commitmentId,
      this.config.validatorId,
      commitment.commitmentDigest,
      timestampUs,
      this.config.validatorSetId
    );

    const signature = crypto.sign(null, attestationDigest, this.privateKey);

    const attestation: ValidatorAttestation = {
      commitmentId: commitment.commitmentId,
      validatorId: this.config.validatorId,
      validatorSetId: this.config.validatorSetId,
      observedCommitmentDigest: commitment.commitmentDigest,
      attestationSequence: this.attestationSeq,
      timestampUs,
      signature,
    };

    this.journal.set(journalKey, {
      commitSeq: commitment.commitSeq,
      commitmentId: commitment.commitmentId,
      checkpointDigest: commitment.checkpointDigest,
      attestation,
    });

    return attestation;
  }

  public getSlashingEvidence(): SlashingEvidenceRecord[] {
    return [...this.slashingEvidence];
  }
}
