import { AnchoredCheckpoint, CheckpointStore } from '../checkpoint/types.js';
import { computeCheckpointDigest } from '../checkpoint/anchor.js';
import { PortableTrustProof } from './types.js';
import { OfflineTrustProofVerifier } from './proof.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export class TrustNetworkRecoveryIntegrator {
  /**
   * Validates that the basis checkpoint is identically committed across Local WDB, WORM Vault, and Wolverine Trust Network.
   */
  public static async verifyUnifiedTrustBasis(
    checkpoint: AnchoredCheckpoint | Omit<AnchoredCheckpoint, 'digest'>,
    vaultStore: CheckpointStore,
    portableTrustProof?: PortableTrustProof | undefined
  ): Promise<{
    isVerified: boolean;
    checkpointDigest: Buffer;
  }> {
    const localDigest = computeCheckpointDigest(checkpoint);

    // 1. Verify in WORM Vault Store
    const vaultChk = await vaultStore.get(checkpoint.checkpointId);
    if (!vaultChk) {
      throw new WolverineError(
        WolverineErrorCode.UNTRUSTED_RECOVERY_BASIS,
        `Basis checkpoint ${checkpoint.checkpointId} not found in WORM vault store`
      );
    }
    const vaultDigest = computeCheckpointDigest(vaultChk);
    if (!timingSafeEqualHashes(localDigest, vaultDigest)) {
      throw new WolverineError(
        WolverineErrorCode.UNTRUSTED_RECOVERY_BASIS,
        `EXTERNAL_TRUST_DIVERGENCE: Local checkpoint digest does not match WORM store digest`
      );
    }

    // 2. Verify in Portable Trust Proof if present
    if (portableTrustProof) {
      const proofResult = OfflineTrustProofVerifier.verifyPortableProof(portableTrustProof);
      if (!proofResult.isValid) {
        throw new WolverineError(
          WolverineErrorCode.UNTRUSTED_RECOVERY_BASIS,
          `EXTERNAL_TRUST_DIVERGENCE: Portable trust proof verification failed: ${proofResult.reason}`
        );
      }

      const proofDigest = Buffer.from(portableTrustProof.commitment.checkpointDigestHex, 'hex');
      if (!timingSafeEqualHashes(localDigest, proofDigest)) {
        throw new WolverineError(
          WolverineErrorCode.UNTRUSTED_RECOVERY_BASIS,
          `EXTERNAL_TRUST_DIVERGENCE: Checkpoint digest does not match finalized Wolverine Trust Proof digest`
        );
      }
    }

    return {
      isVerified: true,
      checkpointDigest: localDigest,
    };
  }
}
