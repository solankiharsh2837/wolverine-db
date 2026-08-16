import crypto from 'node:crypto';
import { TrustCommitment, ValidatorAttestation } from './types.js';
import { verifyCustomerCommitment } from './commitment.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export function computeAttestationDigest(
  commitmentId: string,
  validatorId: string,
  observedCommitmentDigest: Buffer,
  timestampUs: bigint
): Buffer {
  const domain = Buffer.from('WDB:ATTEST:v2:', 'utf8');

  const cmtBytes = Buffer.from(commitmentId, 'utf8');
  const cmtLen = Buffer.alloc(4);
  cmtLen.writeUInt32BE(cmtBytes.length, 0);

  const valBytes = Buffer.from(validatorId, 'utf8');
  const valLen = Buffer.alloc(4);
  valLen.writeUInt32BE(valBytes.length, 0);

  const timeBuf = Buffer.alloc(8);
  timeBuf.writeBigUInt64BE(timestampUs);

  return crypto
    .createHash('sha256')
    .update(
      Buffer.concat([
        domain,
        cmtLen,
        cmtBytes,
        valLen,
        valBytes,
        observedCommitmentDigest,
        timeBuf,
      ])
    )
    .digest();
}

export class TrustValidator {
  public readonly validatorId: string;
  public readonly validatorSetId: string;
  public readonly publicKey: Buffer;
  private readonly privateKey: crypto.KeyObject;
  private attestationSeq: bigint = 0n;

  // Track sequence history per tenant:database -> { lastSeq, lastCommitmentId, lastDigest, attestation }
  private tenantHistory = new Map<
    string,
    { lastSeq: bigint; lastCommitmentId: string; lastDigest: Buffer; attestation: ValidatorAttestation }
  >();

  constructor(
    validatorId: string,
    validatorSetId: string = 'valset-genesis',
    keyPair?: { publicKey: Buffer; privateKey: crypto.KeyObject }
  ) {
    this.validatorId = validatorId;
    this.validatorSetId = validatorSetId;

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
    expectedCustomerPubkey: Buffer
  ): ValidatorAttestation {
    // 1. Verify Customer Signature & Tenant Identity
    const isCustomerValid = verifyCustomerCommitment(commitment, expectedCustomerPubkey);
    if (!isCustomerValid) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Validator ${this.validatorId} rejected: Invalid customer signature or tenant binding`
      );
    }

    // 2. Enforce Monotonic Sequence Order
    const tenantKey = `${commitment.tenantId}:${commitment.databaseId}`;
    const prior = this.tenantHistory.get(tenantKey);

    if (prior) {
      // Idempotent retry: if this validator already attested this exact same commitment, return cached attestation
      if (
        commitment.commitSeq === prior.lastSeq &&
        commitment.commitmentId === prior.lastCommitmentId &&
        Buffer.compare(commitment.commitmentDigest, prior.lastDigest) === 0
      ) {
        return prior.attestation;
      }

      if (commitment.commitSeq <= prior.lastSeq) {
        throw new WolverineError(
          WolverineErrorCode.HISTORY_MUTATION_DETECTED,
          `Validator ${this.validatorId} detected sequence rollback or duplication: seq ${commitment.commitSeq} <= ${prior.lastSeq}`
        );
      }

      if (Buffer.compare(commitment.previousTrustCommitment, prior.lastDigest) !== 0) {
        throw new WolverineError(
          WolverineErrorCode.HISTORY_MUTATION_DETECTED,
          `Validator ${this.validatorId} detected broken chain: previous digest mismatch`
        );
      }
    }

    this.attestationSeq += 1n;
    const timestampUs = BigInt(Date.now()) * 1000n;

    // 3. Compute Digest and Sign Attestation
    const attestationDigest = computeAttestationDigest(
      commitment.commitmentId,
      this.validatorId,
      commitment.commitmentDigest,
      timestampUs
    );

    const signature = crypto.sign(null, attestationDigest, this.privateKey);

    const attestation: ValidatorAttestation = {
      commitmentId: commitment.commitmentId,
      validatorId: this.validatorId,
      validatorSetId: this.validatorSetId,
      observedCommitmentDigest: commitment.commitmentDigest,
      attestationSequence: this.attestationSeq,
      timestampUs,
      signature,
    };

    // Update local history
    this.tenantHistory.set(tenantKey, {
      lastSeq: commitment.commitSeq,
      lastCommitmentId: commitment.commitmentId,
      lastDigest: commitment.commitmentDigest,
      attestation,
    });

    return attestation;
  }

  public verifyAttestation(
    attestation: ValidatorAttestation,
    expectedValidatorPubkey: Buffer
  ): boolean {
    const digest = computeAttestationDigest(
      attestation.commitmentId,
      attestation.validatorId,
      attestation.observedCommitmentDigest,
      attestation.timestampUs
    );

    const spkiBuffer = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      expectedValidatorPubkey,
    ]);

    try {
      const pubKeyObject = crypto.createPublicKey({
        key: spkiBuffer,
        format: 'der',
        type: 'spki',
      });

      return crypto.verify(null, digest, pubKeyObject, attestation.signature);
    } catch {
      return false;
    }
  }
}
