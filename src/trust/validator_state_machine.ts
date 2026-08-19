import crypto from 'node:crypto';
import { CanonicalCommitment, computeCanonicalCommitmentDigest, verifyDualAttestation } from './commitment.js';
import { ValidatorLockTable, SequenceLockRecord } from './validator_lock.js';
import { ValidatorDurableJournal } from './validator_journal.js';
import { ValidatorSetManager } from './validator_set.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export enum ValidatorLifecycleState {
  BOOTING = 'BOOTING',
  READY = 'READY',
  VALIDATING = 'VALIDATING',
  LOCKED = 'LOCKED',
  ATTESTED = 'ATTESTED',
  HALTED_FAULT = 'HALTED_FAULT',
}

export interface ValidatorAttestation {
  validatorId: string;
  commitmentId: string;
  commitmentDigestHex: string;
  epoch: number;
  commitSeq: bigint;
  attestationTimestampUs: bigint;
  signatureHex: string;
}

export class FormalValidatorStateMachine {
  public readonly validatorId: string;
  private privateKey: crypto.KeyObject;
  private validatorSetManager: ValidatorSetManager;
  private lockTable: ValidatorLockTable;
  private journal?: ValidatorDurableJournal;

  private state: ValidatorLifecycleState = ValidatorLifecycleState.BOOTING;
  private expectedAgentPubkey?: Buffer;
  private expectedCustomerPubkey?: Buffer;

  private lastCommitSeq: bigint = 0n;
  private lastCommitmentDigestHex: string = '0000000000000000000000000000000000000000000000000000000000000000';

  constructor(
    validatorId: string,
    privateKey: crypto.KeyObject,
    validatorSetManager: ValidatorSetManager,
    journal?: ValidatorDurableJournal,
    expectedAgentPubkey?: Buffer,
    expectedCustomerPubkey?: Buffer
  ) {
    this.validatorId = validatorId;
    this.privateKey = privateKey;
    this.validatorSetManager = validatorSetManager;
    this.journal = journal;
    this.lockTable = new ValidatorLockTable(validatorId);
    this.expectedAgentPubkey = expectedAgentPubkey;
    this.expectedCustomerPubkey = expectedCustomerPubkey;
  }

  public get lifecycleState(): ValidatorLifecycleState {
    return this.state;
  }

  public get sequence(): bigint {
    return this.lastCommitSeq;
  }

  public get lastDigest(): string {
    return this.lastCommitmentDigestHex;
  }

  /**
   * Initializes the validator state machine, replaying durable locks from disk.
   */
  public async initialize(): Promise<void> {
    this.state = ValidatorLifecycleState.BOOTING;

    if (this.journal) {
      const records = await this.journal.replay();
      for (const rec of records) {
        this.lockTable.restoreLockFromJournal(rec);
        if (rec.commitSeq > this.lastCommitSeq) {
          this.lastCommitSeq = rec.commitSeq;
          this.lastCommitmentDigestHex = rec.commitmentDigestHex;
        }
      }
    }

    this.state = ValidatorLifecycleState.READY;
  }

  /**
   * Evaluates a commitment, executes the lock-before-sign sequence, and emits an attestation.
   */
  public async attestCommitment(commitment: CanonicalCommitment): Promise<ValidatorAttestation> {
    if (this.state !== ValidatorLifecycleState.READY && this.state !== ValidatorLifecycleState.ATTESTED) {
      throw new WolverineError(
        WolverineErrorCode.DATABASE_CONNECTION_ERROR,
        `Cannot attest commitment: validator is in state ${this.state}`
      );
    }

    this.state = ValidatorLifecycleState.VALIDATING;

    try {
      // 1. Recompute canonical digest D_n and verify dual attestation
      const { commitmentDigest } = verifyDualAttestation(
        commitment,
        this.expectedAgentPubkey,
        this.expectedCustomerPubkey
      );
      const digestHex = commitmentDigest.toString('hex');

      // 2. Epoch Invariant Check
      if (commitment.epoch !== this.validatorSetManager.epoch) {
        throw new WolverineError(
          WolverineErrorCode.UNAUTHORIZED_MUTATION,
          `Epoch mismatch: validator active in epoch ${this.validatorSetManager.epoch}, commitment from epoch ${commitment.epoch}`
        );
      }

      // 3. Sequence & Predecessor Invariant Checks
      const commitSeq = commitment.commitSeq;

      if (commitSeq <= this.lastCommitSeq && this.lastCommitSeq > 0n) {
        // Check for idempotent duplicate submission
        const existingLock = this.lockTable.getLock(
          commitment.tenantId,
          commitment.databaseId,
          commitment.epoch,
          commitSeq
        );

        if (existingLock && existingLock.commitmentDigestHex === digestHex) {
          let signatureHex = existingLock.validatorSignatureHex;
          if (!signatureHex) {
            const attDigest = this.computeAttestationDigest(
              commitmentDigest,
              commitment.epoch,
              commitSeq,
              existingLock.lockedAtUs
            );
            const signatureBuf = crypto.sign(null, attDigest, this.privateKey);
            signatureHex = signatureBuf.toString('hex');
            this.lockTable.attachSignature(
              commitment.tenantId,
              commitment.databaseId,
              commitment.epoch,
              commitSeq,
              signatureHex
            );
          }

          this.state = ValidatorLifecycleState.ATTESTED;
          return {
            validatorId: this.validatorId,
            commitmentId: commitment.commitmentId,
            commitmentDigestHex: digestHex,
            epoch: commitment.epoch,
            commitSeq,
            attestationTimestampUs: existingLock.lockedAtUs,
            signatureHex,
          };
        }

        // Conflicting commitment for locked sequence -> triggers EQUIVOCATION_DETECTED
        if (existingLock && existingLock.commitmentDigestHex !== digestHex) {
          this.lockTable.checkOrAcquireLock(
            commitment.tenantId,
            commitment.databaseId,
            commitment.epoch,
            commitSeq,
            digestHex
          );
        }

        throw new WolverineError(
          WolverineErrorCode.HISTORY_MUTATION_DETECTED,
          `Sequence rollback rejected: sequence ${commitSeq} <= last committed sequence ${this.lastCommitSeq}`
        );
      }

      if (this.lastCommitSeq > 0n) {
        if (commitSeq !== this.lastCommitSeq + 1n) {
          throw new WolverineError(
            WolverineErrorCode.SEQUENCE_GAP_DETECTED,
            `Sequence gap rejected: expected ${this.lastCommitSeq + 1n}, observed ${commitSeq}`
          );
        }

        if (commitment.previousCommitmentDigestHex !== this.lastCommitmentDigestHex) {
          throw new WolverineError(
            WolverineErrorCode.CHANGE_HASH_MISMATCH,
            `Predecessor digest mismatch: expected ${this.lastCommitmentDigestHex}, observed ${commitment.previousCommitmentDigestHex}`
          );
        }
      }

      // 4. Check or acquire non-equivocation lock
      const lockResult = this.lockTable.checkOrAcquireLock(
        commitment.tenantId,
        commitment.databaseId,
        commitment.epoch,
        commitSeq,
        digestHex
      );

      this.state = ValidatorLifecycleState.LOCKED;

      const attestationTimestampUs = BigInt(Date.now()) * 1000n;
      const lockRecord: SequenceLockRecord = {
        tenantId: commitment.tenantId,
        databaseId: commitment.databaseId,
        epoch: commitment.epoch,
        commitSeq,
        commitmentDigestHex: digestHex,
        lockedAtUs: attestationTimestampUs,
      };

      // 5. DURABLE LOCK BEFORE SIGN: Flush to disk with synchronous fsync
      if (this.journal) {
        await this.journal.appendLock(lockRecord);
      }

      // 6. Compute Ed25519 Attestation Signature ONLY AFTER DURABLE PERSISTENCE
      const attestationDigest = this.computeAttestationDigest(
        commitmentDigest,
        commitment.epoch,
        commitSeq,
        attestationTimestampUs
      );

      const signatureBuf = crypto.sign(null, attestationDigest, this.privateKey);
      const signatureHex = signatureBuf.toString('hex');

      // Attach signature to memory lock table
      this.lockTable.attachSignature(
        commitment.tenantId,
        commitment.databaseId,
        commitment.epoch,
        commitSeq,
        signatureHex
      );

      // Advance sequence state
      this.lastCommitSeq = commitSeq;
      this.lastCommitmentDigestHex = digestHex;
      this.state = ValidatorLifecycleState.ATTESTED;

      return {
        validatorId: this.validatorId,
        commitmentId: commitment.commitmentId,
        commitmentDigestHex: digestHex,
        epoch: commitment.epoch,
        commitSeq,
        attestationTimestampUs,
        signatureHex,
      };
    } catch (err: any) {
      this.state = ValidatorLifecycleState.READY;
      throw err;
    }
  }

  public computeAttestationDigest(
    commitmentDigest: Buffer,
    epoch: number,
    commitSeq: bigint,
    timestampUs: bigint
  ): Buffer {
    const valIdBuf = Buffer.from(this.validatorId, 'utf8');
    const valIdLenBuf = Buffer.alloc(2);
    valIdLenBuf.writeUInt16BE(valIdBuf.length, 0);

    const epochBuf = Buffer.alloc(4);
    epochBuf.writeUInt32BE(epoch, 0);

    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(commitSeq, 0);

    const timeBuf = Buffer.alloc(8);
    timeBuf.writeBigInt64BE(timestampUs, 0);

    const preimage = Buffer.concat([
      Buffer.from('WDB:VAL_ATTEST:v2:', 'utf8'),
      commitmentDigest,
      valIdLenBuf,
      valIdBuf,
      epochBuf,
      seqBuf,
      timeBuf,
    ]);

    return crypto.createHash('sha256').update(preimage).digest();
  }

  public getSlashingEvidence() {
    return this.lockTable.getSlashingEvidence();
  }
}
