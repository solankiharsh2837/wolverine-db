import crypto from 'node:crypto';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface ValidatorNode {
  validatorId: string;
  publicKeyHex: string;
  weight: number;
}

export interface CanonicalValidatorSet {
  validatorSetId: string;
  epoch: number;
  quorumThreshold: number; // M
  totalValidators: number; // N
  validators: ValidatorNode[];
}

export class ValidatorSetManager {
  private activeSet: CanonicalValidatorSet;
  private keyObjects = new Map<string, crypto.KeyObject>();

  constructor(set: CanonicalValidatorSet) {
    if (set.validators.length !== set.totalValidators) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_CONFIGURATION,
        `Validator set count mismatch: expected ${set.totalValidators}, provided ${set.validators.length}`
      );
    }

    const minQuorum = Math.floor((2 * set.totalValidators) / 3) + 1;
    if (set.quorumThreshold < minQuorum) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_CONFIGURATION,
        `Quorum threshold ${set.quorumThreshold} is below Byzantine safety minimum ${minQuorum} for N=${set.totalValidators}`
      );
    }

    this.activeSet = { ...set, validators: [...set.validators] };

    for (const val of set.validators) {
      const pubkeyBuf = Buffer.from(val.publicKeyHex, 'hex');
      const keyObj = crypto.createPublicKey({
        key: pubkeyBuf,
        format: 'der',
        type: 'spki',
      });
      this.keyObjects.set(val.validatorId, keyObj);
    }
  }

  public get validatorSetId(): string {
    return this.activeSet.validatorSetId;
  }

  public get epoch(): number {
    return this.activeSet.epoch;
  }

  public get quorumThreshold(): number {
    return this.activeSet.quorumThreshold;
  }

  public get totalValidators(): number {
    return this.activeSet.totalValidators;
  }

  public getValidator(validatorId: string): ValidatorNode | undefined {
    return this.activeSet.validators.find((v) => v.validatorId === validatorId);
  }

  public getPublicKeyObject(validatorId: string): crypto.KeyObject | undefined {
    return this.keyObjects.get(validatorId);
  }

  public hasValidator(validatorId: string): boolean {
    return this.keyObjects.has(validatorId);
  }

  public getActiveSet(): CanonicalValidatorSet {
    return {
      ...this.activeSet,
      validators: this.activeSet.validators.map((v) => ({ ...v })),
    };
  }
}
