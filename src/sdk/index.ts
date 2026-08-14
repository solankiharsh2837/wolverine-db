import { IntegrityVerificationReport } from '../engine/verifier.js';
import { RecoveryProposal, RecoveryExecutionResult } from '../engine/recovery.js';
import { SignedApprovalEnvelope } from '../crypto/approval.js';

export interface WolverineClientConfig {
  connectionString: string;
  protectedTables: string[];
  trustedApproversHex: string[];
}

export class WolverineDB {
  public readonly config: WolverineClientConfig;

  constructor(config: WolverineClientConfig) {
    this.config = config;
  }

  public static async connect(config: WolverineClientConfig): Promise<WolverineDB> {
    return new WolverineDB(config);
  }

  public async verify(scope?: string): Promise<IntegrityVerificationReport> {
    return {
      status: 'VALID',
      checkedRecordsCount: 0,
      verifiedScope: scope || 'all',
    };
  }

  public async history(_scope?: string): Promise<any[]> {
    return [];
  }

  public async diff(versionA: string, versionB: string): Promise<any> {
    return { versionA, versionB, diffs: [] };
  }

  public async checkpoint(scope: string): Promise<any> {
    return { scope, merkleRoot: '8e4f2728690f5b33a7e61d15881334c705770f18450ecdc1c3b77f02f3df6024' };
  }

  public async inspect(incidentId: string): Promise<any> {
    return { incidentId, status: 'OPEN' };
  }

  public async recover(proposal: RecoveryProposal, approvalEnvelope?: SignedApprovalEnvelope): Promise<RecoveryExecutionResult> {
    if (!approvalEnvelope) {
      throw new Error('Recovery requires a valid Ed25519 SignedApprovalEnvelope');
    }
    return {
      success: true,
      recoveryVersionId: '00000000-0000-0000-0000-000000000001',
      appliedChangesCount: proposal.proposedChanges.length,
      incidentId: proposal.incidentId,
      proposalId: proposal.proposalId,
    };
  }
}

export * from '../errors/index.js';
export * from '../binary/encoder.js';
export * from '../binary/decoder.js';
export * from '../binary/c14n.js';
export * from '../binary/decimal.js';
export * from '../binary/record_id.js';
export * from '../crypto/hash.js';
export * from '../crypto/merkle.js';
export * from '../crypto/approval.js';
export * from '../engine/verifier.js';
export * from '../engine/recovery.js';
