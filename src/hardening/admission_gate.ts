import crypto from 'node:crypto';
import { ValidatorSetManager } from '../trust/validator_set.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export enum BootAdmissionState {
  BOOTING = 'BOOTING',
  IDENTITY_VALIDATING = 'IDENTITY_VALIDATING',
  PROTOCOL_VERSION_VALIDATING = 'PROTOCOL_VERSION_VALIDATING',
  VALIDATOR_SET_VALIDATING = 'VALIDATOR_SET_VALIDATING',
  JOURNAL_VALIDATING = 'JOURNAL_VALIDATING',
  EPOCH_VALIDATING = 'EPOCH_VALIDATING',
  READY = 'READY',
  QUARANTINED = 'QUARANTINED',
}

export interface DaemonBootParameters {
  validatorId: string;
  protocolVersion: number;
  epoch: number;
  privateKey: crypto.KeyObject;
  validatorSetManager: ValidatorSetManager;
  hasUnresolvedDisasters?: boolean;
}

export interface AdmissionEvaluationResult {
  admitted: boolean;
  state: BootAdmissionState;
  reason: string;
}

export class CryptographicAdmissionGate {
  /**
   * Strictly evaluates admission prerequisites before allowing a daemon into READY state.
   */
  public static evaluateAdmission(params: DaemonBootParameters): AdmissionEvaluationResult {
    let state = BootAdmissionState.IDENTITY_VALIDATING;

    // 1. Identity Validation: Check if validatorId exists in authoritative set
    if (!params.validatorSetManager.hasValidator(params.validatorId)) {
      return {
        admitted: false,
        state: BootAdmissionState.QUARANTINED,
        reason: `ADMISSION_DENIED: Unknown validator identity "${params.validatorId}"`,
      };
    }

    // 2. Protocol Version Validation
    state = BootAdmissionState.PROTOCOL_VERSION_VALIDATING;
    if (params.protocolVersion !== 2) {
      return {
        admitted: false,
        state: BootAdmissionState.QUARANTINED,
        reason: `ADMISSION_DENIED: Incompatible protocol version ${params.protocolVersion} (expected 2)`,
      };
    }

    // 3. Validator Set Key Alignment Validation
    state = BootAdmissionState.VALIDATOR_SET_VALIDATING;
    const registeredPubkeyObj = params.validatorSetManager.getPublicKeyObject(params.validatorId);
    if (!registeredPubkeyObj) {
      return {
        admitted: false,
        state: BootAdmissionState.QUARANTINED,
        reason: 'ADMISSION_DENIED: Missing public key in validator set',
      };
    }

    // Test sign & verify to prove private key matches registered public key
    try {
      const probeMessage = Buffer.from(`WDB:BOOT_PROBE:${Date.now()}`, 'utf8');
      const probeSig = crypto.sign(null, probeMessage, params.privateKey);
      const isMatch = crypto.verify(null, probeMessage, registeredPubkeyObj, probeSig);

      if (!isMatch) {
        return {
          admitted: false,
          state: BootAdmissionState.QUARANTINED,
          reason: 'ADMISSION_DENIED: Private key does not correspond to registered public key',
        };
      }
    } catch (err: any) {
      return {
        admitted: false,
        state: BootAdmissionState.QUARANTINED,
        reason: `ADMISSION_DENIED: Cryptographic key validation failed: ${err.message}`,
      };
    }

    // 4. Journal / Disaster State Validation
    state = BootAdmissionState.JOURNAL_VALIDATING;
    if (params.hasUnresolvedDisasters) {
      return {
        admitted: false,
        state: BootAdmissionState.QUARANTINED,
        reason: 'ADMISSION_DENIED: Node has unresolved quarantined disasters on disk',
      };
    }

    // 5. Epoch Validation
    state = BootAdmissionState.EPOCH_VALIDATING;
    if (params.epoch !== params.validatorSetManager.epoch) {
      return {
        admitted: false,
        state: BootAdmissionState.QUARANTINED,
        reason: `ADMISSION_DENIED: Epoch mismatch (configured: ${params.epoch}, set: ${params.validatorSetManager.epoch})`,
      };
    }

    return {
      admitted: true,
      state: BootAdmissionState.READY,
      reason: 'ADMISSION_GRANTED: All cryptographic checks passed',
    };
  }
}
