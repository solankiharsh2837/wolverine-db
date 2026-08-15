import {
  ReconstructionManifest,
  ReconstructionProof,
} from './types.js';
import { StateReconstructionCoordinator, ReconstructionWorkflowOptions } from './coordinator.js';
import { computeReconstructionDigest } from './manifest.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export interface CliCommandResult {
  command: string;
  success: boolean;
  output: string;
  data?: unknown;
}

export class ReconstructionCli {
  /**
   * wdb frontier --database <id>
   */
  public static async executeFrontier(
    options: ReconstructionWorkflowOptions
  ): Promise<CliCommandResult> {
    const { manifest } = await StateReconstructionCoordinator.planReconstruction(options);
    const output = [
      `=== WolverineDB Verified State Frontier ===`,
      `Database ID:              ${manifest.databaseId}`,
      `Starting Checkpoint:      ${manifest.sourceCheckpointId} (CommitSeq ${manifest.sourceCheckpointCommitSeq})`,
      `Verified Frontier Seq:    ${manifest.endingCommitSeq}`,
      `Authorized Preserved:     ${manifest.replayedChangeIds.length} mutations`,
      `Compromised Excluded:     ${manifest.excludedChangeIds.length} mutations`,
      `Compromise Reason:        ${manifest.recoveryBoundary.compromiseReason}`,
      `Reconstruction Digest:    ${manifest.reconstructionDigest.toString('hex')}`,
    ].join('\n');

    return {
      command: `wdb frontier --database ${options.databaseId}`,
      success: true,
      output,
      data: manifest,
    };
  }

  /**
   * wdb reconstruct --database <id>
   */
  public static async executeReconstruct(
    options: ReconstructionWorkflowOptions
  ): Promise<CliCommandResult> {
    const { manifest } = await StateReconstructionCoordinator.planReconstruction(options);
    return {
      command: `wdb reconstruct --database ${options.databaseId}`,
      success: true,
      output: JSON.stringify(manifest, null, 2),
      data: manifest,
    };
  }

  /**
   * wdb recovery-certificate --recovery-id <id>
   */
  public static async executeCertificate(
    options: ReconstructionWorkflowOptions
  ): Promise<CliCommandResult> {
    const { manifest, advisoryProposal } = await StateReconstructionCoordinator.planReconstruction(options);
    const { certificate, terminalOutput } = await StateReconstructionCoordinator.executeVerifiedRestoration(
      options,
      manifest,
      advisoryProposal
    );

    return {
      command: `wdb recovery-certificate --recovery-id ${certificate.recoveryId}`,
      success: true,
      output: terminalOutput,
      data: certificate,
    };
  }

  /**
   * wdb recovery-verify --recovery-id <id>
   */
  public static verifyReconstructionProof(
    manifest: ReconstructionManifest,
    proof: ReconstructionProof
  ): boolean {
    const expectedDigest = computeReconstructionDigest(manifest);
    if (!timingSafeEqualHashes(expectedDigest, proof.manifestDigest)) {
      return false;
    }
    if (!timingSafeEqualHashes(manifest.reconstructedMerkleRoot, proof.reconstructedMerkleRoot)) {
      return false;
    }
    return true;
  }
}
