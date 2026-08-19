import crypto from 'node:crypto';
import { DependencyEdge, StateDependencyGraph } from './types.js';
import { ChangeRecordData, MutationOperation } from '../protocol/types.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { ReconstructedDatabaseState } from '../reconstruction/types.js';

export function computeDependencyGraphDigest(graph: StateDependencyGraph): Buffer {
  const domain = Buffer.from('WDB:DEP_GRAPH:v1:', 'utf8');

  const serializableEdges = graph.dependencies.map((d) => ({
    targetChangeId: d.targetChangeId,
    targetCommitSeq: d.targetCommitSeq.toString(),
    dependsOnChangeId: d.dependsOnChangeId,
    dependsOnCommitSeq: d.dependsOnCommitSeq.toString(),
    dependencyType: d.dependencyType,
    isDependencySatisfied: d.isDependencySatisfied,
    failureReason: d.failureReason || null,
  }));

  const canonicalPayload = canonicalizeJson({
    dependencies: serializableEdges,
    blockedChangeIds: graph.blockedChangeIds,
    conflictChangeIds: graph.conflictChangeIds,
  });

  return crypto
    .createHash('sha256')
    .update(Buffer.concat([domain, Buffer.from(canonicalPayload, 'utf8')]))
    .digest();
}

export class StateDependencyGraphBuilder {
  private dependencies: DependencyEdge[] = [];
  private blockedChangeIds: string[] = [];
  private conflictChangeIds: string[] = [];

  // Track the latest producing commit sequence, status, and values for each row: table:pkHex
  private rowVersionLedger = new Map<
    string,
    {
      lastSeq: bigint;
      changeId: string;
      isExcluded: boolean;
      operation: MutationOperation;
      values: Record<string, unknown>;
    }
  >();

  constructor(initialCheckpointState?: ReconstructedDatabaseState) {
    if (initialCheckpointState) {
      for (const [table, rows] of initialCheckpointState.entries()) {
        for (const [pkHex, row] of rows.entries()) {
          this.rowVersionLedger.set(`${table}:${pkHex}`, {
            lastSeq: row.commitSeq,
            changeId: row.versionId || 'checkpoint-root',
            isExcluded: false,
            operation: MutationOperation.INSERT,
            values: { ...row.values },
          });
        }
      }
    }
  }

  public analyzeMutationDependency(
    change: ChangeRecordData,
    commitSeq: bigint,
    isDirectlyExcluded: boolean
  ): {
    isBlocked: boolean;
    isConflict: boolean;
    reason?: string | undefined;
  } {
    const key = `${change.tableId}:${change.recordId.toString('hex')}`;
    const priorState = this.rowVersionLedger.get(key);

    let isBlocked = false;
    let isConflict = false;
    let reason: string | undefined;

    if (change.operation === MutationOperation.UPDATE || change.operation === MutationOperation.DELETE) {
      if (priorState) {
        const edge: DependencyEdge = {
          targetChangeId: change.versionId,
          targetCommitSeq: commitSeq,
          dependsOnChangeId: priorState.changeId,
          dependsOnCommitSeq: priorState.lastSeq,
          dependencyType: 'ROW_VERSION_PREDECESSOR',
          isDependencySatisfied: !priorState.isExcluded,
          failureReason: priorState.isExcluded
            ? `DEPENDS_ON_EXCLUDED_MUTATION(seq=${priorState.lastSeq})`
            : undefined,
        };
        this.dependencies.push(edge);

        if (priorState.isExcluded) {
          isBlocked = true;
          reason = `DEPENDENCY_BLOCKED: Depends on excluded row version created at seq ${priorState.lastSeq}`;
          this.blockedChangeIds.push(change.versionId);
        } else if (priorState.operation === MutationOperation.DELETE) {
          isConflict = true;
          reason = `STATE_CONFLICT: Attempted UPDATE/DELETE on row already deleted at seq ${priorState.lastSeq}`;
          this.conflictChangeIds.push(change.versionId);
        } else if (change.operation === MutationOperation.UPDATE && change.fieldSet.old) {
          // Verify semantic consistency of fieldSet.old against reconstructed row values
          const oldExpected = change.fieldSet.old as Record<string, unknown>;
          for (const [fName, fVal] of Object.entries(oldExpected)) {
            if (fVal !== undefined && priorState.values[fName] !== undefined) {
              if (canonicalizeJson(priorState.values[fName]) !== canonicalizeJson(fVal)) {
                isConflict = true;
                reason = `STATE_CONFLICT: Semantic state divergence on field "${fName}" (expected "${canonicalizeJson(fVal)}", reconstructed "${canonicalizeJson(priorState.values[fName])}")`;
                this.conflictChangeIds.push(change.versionId);
                break;
              }
            }
          }
        }
      } else {
        isConflict = true;
        reason = 'STATE_CONFLICT: Mutation on non-existent row';
        this.conflictChangeIds.push(change.versionId);
      }
    } else if (change.operation === MutationOperation.INSERT) {
      if (priorState && !priorState.isExcluded && priorState.operation !== MutationOperation.DELETE) {
        isConflict = true;
        reason = `STATE_CONFLICT: Key collision on INSERT with existing live row version from seq ${priorState.lastSeq}`;
        this.conflictChangeIds.push(change.versionId);
      }
    }

    // Update row version ledger if not excluded
    const currentValues =
      change.operation === MutationOperation.UPDATE && priorState
        ? { ...priorState.values, ...((change.fieldSet.new as Record<string, unknown>) || {}) }
        : ((change.fieldSet.new as Record<string, unknown>) || {});

    this.rowVersionLedger.set(key, {
      lastSeq: commitSeq,
      changeId: change.versionId,
      isExcluded: isDirectlyExcluded || isBlocked || isConflict,
      operation: change.operation,
      values: currentValues,
    });

    return { isBlocked, isConflict, reason };
  }

  public build(): StateDependencyGraph {
    return {
      dependencies: this.dependencies,
      blockedChangeIds: this.blockedChangeIds,
      conflictChangeIds: this.conflictChangeIds,
    };
  }
}
