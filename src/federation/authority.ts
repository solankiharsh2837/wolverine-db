import crypto from 'node:crypto';
import { FederatedRecoveryAuthorizationRequest } from './types.js';
import { NodeRegistry } from './identity.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export function computeFederatedRecoveryDigest(
  proposalId: string,
  incidentId: string,
  protectedScope: string,
  proposedChangesHash: Buffer
): Buffer {
  const domain = Buffer.from('WDB:FED_REC_AUTH:v1:', 'utf8');

  const propIdBuf = Buffer.alloc(16);
  Buffer.from(proposalId.replace(/-/g, ''), 'hex').copy(propIdBuf, 0);

  const incIdBuf = Buffer.from(incidentId, 'utf8');
  const scopeBuf = Buffer.from(protectedScope, 'utf8');

  const preimage = Buffer.concat([domain, propIdBuf, incIdBuf, scopeBuf, proposedChangesHash]);
  return crypto.createHash('sha256').update(preimage).digest();
}

export class FederatedRecoveryAuthority {
  private nodeRegistry: NodeRegistry;

  constructor(nodeRegistry: NodeRegistry) {
    this.nodeRegistry = nodeRegistry;
  }

  /**
   * Verifies that a federated recovery proposal satisfies multi-node quorum threshold.
   */
  public verifyFederatedAuthorization(
    request: FederatedRecoveryAuthorizationRequest,
    requiredQuorum: number
  ): {
    authorized: boolean;
    validSigners: string[];
    rejectedSigners: Array<{ nodeId: string; reason: string }>;
  } {
    const validSigners: string[] = [];
    const rejectedSigners: Array<{ nodeId: string; reason: string }> = [];

    const digest = computeFederatedRecoveryDigest(
      request.proposalId,
      request.incidentId,
      request.protectedScope,
      request.proposedChangesHash
    );

    for (const sigEntry of request.signatures) {
      // 1. Proposing node cannot sign (separation of duties)
      if (sigEntry.nodeId === request.proposingNodeId) {
        rejectedSigners.push({
          nodeId: sigEntry.nodeId,
          reason: 'Proposing node cannot approve its own recovery proposal',
        });
        continue;
      }

      // 2. Node must be in TRUSTED status
      const node = this.nodeRegistry.getNode(sigEntry.nodeId);
      if (!node || node.status !== 'TRUSTED') {
        rejectedSigners.push({
          nodeId: sigEntry.nodeId,
          reason: `Node "${sigEntry.nodeId}" is not in TRUSTED status (current: ${node?.status || 'UNKNOWN'})`,
        });
        continue;
      }

      // 3. Verify signature
      let isSigValid = false;
      try {
        const pubKeyObject = crypto.createPublicKey({
          key: Buffer.concat([
            Buffer.from('302a300506032b6570032100', 'hex'),
            node.publicKey,
          ]),
          format: 'der',
          type: 'spki',
        });
        isSigValid = crypto.verify(null, digest, pubKeyObject, sigEntry.signature);
      } catch {
        isSigValid = false;
      }

      if (!isSigValid) {
        rejectedSigners.push({
          nodeId: sigEntry.nodeId,
          reason: 'Invalid cryptographic Ed25519 signature',
        });
        continue;
      }

      validSigners.push(sigEntry.nodeId);
    }

    if (validSigners.length < requiredQuorum) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_APPROVAL_SIGNATURE,
        `FederatedRecoveryAuthorizationFailed: Insufficient valid quorum signatures (${validSigners.length}/${requiredQuorum} required)`
      );
    }

    return {
      authorized: true,
      validSigners,
      rejectedSigners,
    };
  }
}
