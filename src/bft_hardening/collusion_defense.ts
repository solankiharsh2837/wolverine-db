import crypto from 'node:crypto';
import {
  TrustCommitment,
} from '../trust_network/types.js';
import { ByzantineTrustValidator } from '../trust_service/byzantine_validator.js';
import { BftConsensusEngine } from '../trust_service/bft_consensus_engine.js';
import { PersistentTrustLedger } from '../trust_service/persistent_ledger.js';
import { CollusionAttackScenario } from './types.js';

export interface CollusionEvaluationResult {
  isCollusionBlocked: boolean;
  honestValidatorsRejectionCount: number;
  rogueAttestationCount: number;
  totalValidAttestations: number;
  requiredQuorum: number;
  finalityGranted: boolean;
  ledgerCorrupted: boolean;
}

export class CollusionDefenseEvaluator {
  public static async evaluateCollusionAttack(
    validators: Map<string, ByzantineTrustValidator>,
    consensusEngine: BftConsensusEngine,
    ledger: PersistentTrustLedger,
    scenario: CollusionAttackScenario,
    legitCommitment: TrustCommitment,
    customerPubkey: Buffer
  ): Promise<CollusionEvaluationResult> {
    const maliciousCommitment: TrustCommitment = {
      ...legitCommitment,
      commitmentId: crypto.randomUUID(),
      checkpointDigest: scenario.forgedCheckpointDigest,
      customerSignature: crypto.randomBytes(64),
      commitmentDigest: crypto.randomBytes(32),
    };

    let honestRejections = 0;
    let rogueAttestations = 0;
    const collectedAttestations = [];

    // The rogue gateway contacts all 5 validators
    for (const [valId, validator] of validators.entries()) {
      if (valId === scenario.rogueValidatorId) {
        // Rogue validator willingly double-signs the forged commitment
        const rogueAtt = {
          commitmentId: maliciousCommitment.commitmentId,
          validatorId: valId,
          validatorSetId: validator.config.validatorSetId,
          observedCommitmentDigest: maliciousCommitment.commitmentDigest,
          attestationSequence: 1n,
          timestampUs: BigInt(Date.now()) * 1000n,
          signature: crypto.sign(
            null,
            Buffer.from('WDB:ATTEST:v1:ROGUE', 'utf8'),
            (validator as any).privateKey
          ),
        };
        collectedAttestations.push(rogueAtt);
        rogueAttestations++;
      } else {
        // Honest validator evaluates against local journal and customer signature
        try {
          const honestAtt = validator.attestCommitment(maliciousCommitment, customerPubkey);
          collectedAttestations.push(honestAtt);
        } catch {
          honestRejections++;
        }
      }
    }

    let finalityGranted = false;
    try {
      await consensusEngine.processAttestations(maliciousCommitment, collectedAttestations);
      finalityGranted = true;
    } catch {
      finalityGranted = false;
    }

    const ledgerIntegrity = ledger.verifyLedgerIntegrity();

    return {
      isCollusionBlocked: !finalityGranted && honestRejections === 4,
      honestValidatorsRejectionCount: honestRejections,
      rogueAttestationCount: rogueAttestations,
      totalValidAttestations: rogueAttestations,
      requiredQuorum: consensusEngine.requiredQuorum,
      finalityGranted,
      ledgerCorrupted: !ledgerIntegrity,
    };
  }
}
