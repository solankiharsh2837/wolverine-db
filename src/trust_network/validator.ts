import crypto from 'node:crypto';
import { TrustCommitment, ValidatorAttestation } from './types.js';
import { verifyCustomerCommitment } from './commitment.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export function computeAttestationDigest(
  commitmentId: string,
  validatorId: string,
  observedCommitmentDigest: Buffer,
  timestampUs: bigint
): Buffer {
  const domain = Buffer.from('WDB:ATTEST:v1:', 'utf8');
  const timeBuf = Buffer.alloc(8);
  timeBuf.writeBigUInt64BE(timestampUs);

  return crypto
    .createHash('sha256')
    .update(Buffer.concat([
      domain,
      Buffer.from(commitmentId, 'utf8'),
      Buffer.from(validatorId, 'utf8'),
      observedCommitmentDigest,
      timeBuf,
    ]))
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
    expectedCustomerPubkey?: Buffer
  ): ValidatorAttestation {
    // 1. Verify Customer Signature & Commitment Digest
    const isCustomerValid = verifyCustomerCommitment(commitment, expectedCustomerPubkey);
    if (!isCustomerValid) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Validator ${this.validatorId} rejected commitment: Invalid customer signature or tenant binding`
      );
    }

    // 2. Check Sequence Monotonicity & Idempotency
    const key = `${commitment.tenantId}:${commitment.databaseId}`;
    const prior = this.tenantHistory.get(key);

    if (prior) {
      // Idempotent retry check: same seq, same ID, same digest
      if (
        commitment.commitSeq === prior.lastSeq &&
        commitment.commitmentId === prior.lastCommitmentId &&
        timingSafeEqualHashes(commitment.checkpointDigest, prior.lastDigest)
      ) {
        return prior.attestation;
      }

      if (commitment.commitSeq <= prior.lastSeq) {
        throw new WolverineError(
          WolverineErrorCode.HISTORY_MUTATION_DETECTED,
          `Validator ${this.validatorId} rejected commitment: Non-monotonic commitSeq ${commitment.commitSeq} <= ${prior.lastSeq}`
        );
      }
    }

    this.attestationSeq += 1n;
    const timestampUs = BigInt(Date.now()) * 1000n;

    // 3. Compute Attestation Digest & Sign
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

    this.tenantHistory.set(key, {
      lastSeq: commitment.commitSeq,
      lastCommitmentId: commitment.commitmentId,
      lastDigest: commitment.checkpointDigest,
      attestation,
    });

    return attestation;
  }
}
