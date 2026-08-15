import {
  ContinuousReconstructionWorkflowOptions,
  ContinuousStateReconstructionEngine,
} from './continuous_engine.js';
import { ContinuousHistoryClassifier } from './classifier.js';

export interface CliV2CommandResult {
  command: string;
  success: boolean;
  output: string;
  data?: unknown;
}

export class ContinuousReconstructionCli {
  /**
   * wdb frontier
   */
  public static async executeFrontier(
    options: ContinuousReconstructionWorkflowOptions
  ): Promise<CliV2CommandResult> {
    const analysis = ContinuousHistoryClassifier.analyzeHistory(options);
    const lines = [
      '=== WolverineDB Continuous Frontier Analysis ===',
      `Database ID:                        ${options.databaseId}`,
      `Base Checkpoint:                    ${options.baseCheckpoint.checkpointId} (CommitSeq ${options.baseCheckpoint.commitSeq})`,
      `Contiguous Verified Frontier:        CommitSeq ${analysis.contiguousVerifiedFrontierSeq}`,
      `Maximum Reconstructable State:       CommitSeq ${analysis.maximumReconstructableCommitSeq}`,
      `Preserved Mutations:                ${analysis.decisions.filter((d) => d.decision === 'PRESERVE').length}`,
      `Excluded Mutations:                 ${analysis.decisions.filter((d) => d.decision === 'EXCLUDE').length}`,
      `Blocked Mutations:                  ${analysis.decisions.filter((d) => d.decision === 'BLOCK').length}`,
      `Conflicting Mutations:              ${analysis.decisions.filter((d) => d.decision === 'CONFLICT').length}`,
    ];

    return {
      command: `wdb frontier --database ${options.databaseId}`,
      success: true,
      output: lines.join('\n'),
      data: analysis,
    };
  }

  /**
   * wdb reconstruct --explain
   */
  public static async executeReconstructExplain(
    options: ContinuousReconstructionWorkflowOptions
  ): Promise<CliV2CommandResult> {
    const analysis = ContinuousHistoryClassifier.analyzeHistory(options);
    const lines = [
      '================================================================================',
      '                        RECONSTRUCTION DECISION ANALYSIS                        ',
      '================================================================================',
      `Base Checkpoint: ${options.baseCheckpoint.checkpointId} (CommitSeq ${options.baseCheckpoint.commitSeq})`,
      '',
    ];

    for (const d of analysis.decisions) {
      const symbol =
        d.decision === 'PRESERVE'
          ? '✓ PRESERVE'
          : d.decision === 'EXCLUDE'
          ? '✗ EXCLUDE'
          : d.decision === 'BLOCK'
          ? '⚠ BLOCK'
          : '⚡ CONFLICT';

      lines.push(`Seq ${d.commitSeq} [${d.changeId.slice(0, 8)}]  ${symbol}`);
      lines.push(`     Classification: ${d.classification}`);
      lines.push(`     Reason:         ${d.reason}`);
      lines.push(`     Authorization:  ${d.authorizationStatus}`);
      lines.push(`     Provenance:     ${d.provenanceStatus}`);
      lines.push(`     Predecessor:    ${d.predecessorStatus}`);
      lines.push('');
    }
    lines.push('================================================================================');

    return {
      command: `wdb reconstruct --database ${options.databaseId} --explain`,
      success: true,
      output: lines.join('\n'),
      data: analysis.decisions,
    };
  }

  /**
   * wdb reconstruction-graph
   */
  public static async executeReconstructionGraph(
    options: ContinuousReconstructionWorkflowOptions
  ): Promise<CliV2CommandResult> {
    const analysis = ContinuousHistoryClassifier.analyzeHistory(options);
    return {
      command: `wdb reconstruction-graph --database ${options.databaseId}`,
      success: true,
      output: JSON.stringify(
        {
          reconstructionGraphDigest: analysis.reconstructionGraphDigest.toString('hex'),
          dependencyGraphDigest: analysis.dependencyGraphDigest.toString('hex'),
          proofGraph: analysis.proofGraph,
          dependencyGraph: analysis.dependencyGraph,
        },
        null,
        2
      ),
      data: {
        proofGraph: analysis.proofGraph,
        dependencyGraph: analysis.dependencyGraph,
      },
    };
  }

  /**
   * wdb recovery-certificate
   */
  public static async executeRecoveryCertificateV2(
    options: ContinuousReconstructionWorkflowOptions
  ): Promise<CliV2CommandResult> {
    const { analysis, advisoryProposal } =
      await ContinuousStateReconstructionEngine.planContinuousReconstruction(options);
    const { certificateV2, terminalOutput } =
      await ContinuousStateReconstructionEngine.executeContinuousRestoration(
        options,
        analysis,
        advisoryProposal
      );

    return {
      command: `wdb recovery-certificate --recovery-id ${certificateV2.recoveryId}`,
      success: true,
      output: terminalOutput,
      data: certificateV2,
    };
  }
}
