import crypto from 'node:crypto';
import { TrustCommitment } from '../trust_network/types.js';
import { createSignedCustomerCommitment } from '../trust_network/commitment.js';
import { ByzantineTrustValidator } from './byzantine_validator.js';
import { BftConsensusEngine } from './bft_consensus_engine.js';

export interface RogueGatewayAttackResult {
  attackVector: string;
  isBlocked: boolean;
  validatorsRejectedCount: number;
  rejectionReason: string;
  finalityGranted: boolean;
}

export class MaliciousGatewaySimulator {
  private validators: Map<string, ByzantineTrustValidator>;
  private consensusEngine: BftConsensusEngine;

  constructor(
    validators: Map<string, ByzantineTrustValidator>,
    consensusEngine: BftConsensusEngine
  ) {
    this.validators = validators;
    this.consensusEngine = consensusEngine;
  }

  /**
   * Attack Vector 1: Attacker attempts to forge a conflicting digest for the same checkpoint sequence.
   */
  public async attackConflictingCommitment(
    originalCommitment: TrustCommitment,
    fakeCheckpointDigest: Buffer,
    customerPubkey: Buffer,
    customerPrivateKey?: crypto.KeyObject
  ): Promise<RogueGatewayAttackResult> {
    let maliciousCommitment: TrustCommitment;

    if (customerPrivateKey) {
      // Attacker has valid customer signature over the forged digest
      maliciousCommitment = createSignedCustomerCommitment(
        {
          commitmentId: crypto.randomUUID(),
          tenantId: originalCommitment.tenantId,
          databaseId: originalCommitment.databaseId,
          checkpointId: originalCommitment.checkpointId,
          commitSeq: originalCommitment.commitSeq,
          checkpointDigest: fakeCheckpointDigest,
          previousTrustCommitment: originalCommitment.previousTrustCommitment,
        },
        customerPrivateKey,
        customerPubkey
      );
    } else {
      maliciousCommitment = {
        ...originalCommitment,
        commitmentId: crypto.randomUUID(),
        checkpointDigest: fakeCheckpointDigest,
        customerSignature: crypto.randomBytes(64),
        commitmentDigest: crypto.randomBytes(32),
      };
    }

    let rejectedCount = 0;
    let reason = '';
    const attestations = [];

    for (const val of this.validators.values()) {
      try {
        const att = val.attestCommitment(maliciousCommitment, customerPubkey);
        attestations.push(att);
      } catch (err: any) {
        rejectedCount++;
        reason = err.message;
      }
    }

    let finality = false;
    try {
      await this.consensusEngine.processAttestations(maliciousCommitment, attestations);
      finality = true;
    } catch {
      finality = false;
    }

    return {
      attackVector: 'CONFLICTING_COMMITMENT_FORGERY',
      isBlocked: !finality && rejectedCount === this.validators.size,
      validatorsRejectedCount: rejectedCount,
      rejectionReason: reason,
      finalityGranted: finality,
    };
  }

  /**
   * Attack Vector 2: Attacker manufactures fake validator signatures to simulate a fake quorum certificate.
   */
  public async attackForgedValidatorSignatures(
    validCommitment: TrustCommitment
  ): Promise<RogueGatewayAttackResult> {
    const fakeAttestations = Array.from(this.validators.keys()).map((valId) => ({
      commitmentId: validCommitment.commitmentId,
      validatorId: valId,
      validatorSetId: validCommitment.validatorSetId,
      observedCommitmentDigest: validCommitment.commitmentDigest,
      attestationSequence: 1n,
      timestampUs: BigInt(Date.now()) * 1000n,
      signature: crypto.randomBytes(64), // Forged signature!
    }));

    let finality = false;
    let reason = '';
    try {
      await this.consensusEngine.processAttestations(validCommitment, fakeAttestations);
      finality = true;
    } catch (err: any) {
      finality = false;
      reason = err.message;
    }

    return {
      attackVector: 'FORGED_VALIDATOR_SIGNATURES',
      isBlocked: !finality,
      validatorsRejectedCount: this.validators.size,
      rejectionReason: reason,
      finalityGranted: finality,
    };
  }
}
