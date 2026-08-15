import { DurabilityState } from './types.js';
import { PersistentTrustLedger } from '../trust_service/persistent_ledger.js';
import { ByzantineTrustValidator } from '../trust_service/byzantine_validator.js';

export interface HealthEvaluationParams {
  validators: Map<string, { validator: ByzantineTrustValidator; isOnline: boolean }>;
  replicas: Array<{ replicaId: string; stateRoot: Buffer; isOnline: boolean }>;
  ledger: PersistentTrustLedger;
  currentEpoch: number;
  totalConfiguredValidators: number;
  requiredQuorum: number;
}

export class TrustNetworkHealthEvaluator {
  public static evaluateHealth(params: HealthEvaluationParams): {
    durabilityState: DurabilityState;
    activeValidators: number;
    requiredQuorum: number;
    isQuorumAvailable: boolean;
    replicaAgreement: boolean;
    ledgerIntegrity: boolean;
    details: Record<string, unknown>;
  } {
    // 1. Validator Availability
    let activeCount = 0;
    for (const entry of params.validators.values()) {
      if (entry.isOnline) {
        activeCount++;
      }
    }

    const isQuorumAvailable = activeCount >= params.requiredQuorum;

    // 2. Replica State Root Agreement
    const onlineReplicas = params.replicas.filter((r) => r.isOnline);
    let replicaAgreement = true;
    if (onlineReplicas.length > 1) {
      const firstRoot = onlineReplicas[0]!.stateRoot;
      for (let i = 1; i < onlineReplicas.length; i++) {
        if (Buffer.compare(firstRoot, onlineReplicas[i]!.stateRoot) !== 0) {
          replicaAgreement = false;
          break;
        }
      }
    }

    // 3. Ledger Continuity & Integrity
    const ledgerIntegrity = params.ledger.verifyLedgerIntegrity();

    // 4. Derive Durability State
    let durabilityState: DurabilityState = 'HEALTHY';

    if (!ledgerIntegrity) {
      durabilityState = 'CATASTROPHIC_PARTIAL_LOSS';
    } else if (!replicaAgreement) {
      durabilityState = 'PARTITIONED';
    } else if (activeCount === 0) {
      durabilityState = 'CATASTROPHIC_PARTIAL_LOSS';
    } else if (!isQuorumAvailable) {
      durabilityState = 'QUORUM_LOST';
    } else if (activeCount < params.totalConfiguredValidators) {
      durabilityState = 'DEGRADED';
    } else {
      durabilityState = 'HEALTHY';
    }

    return {
      durabilityState,
      activeValidators: activeCount,
      requiredQuorum: params.requiredQuorum,
      isQuorumAvailable,
      replicaAgreement,
      ledgerIntegrity,
      details: {
        totalValidators: params.totalConfiguredValidators,
        activeValidators: activeCount,
        onlineReplicas: onlineReplicas.length,
        ledgerRecordCount: params.ledger.getRecords().length,
      },
    };
  }
}
