import {
  TrustGatewayConfig,
  AttestRpcResponse,
} from './types.js';
import {
  TrustCommitment,
  QuorumCertificate,
  PortableTrustProof,
  TrustLedgerRecord,
} from '../trust_network/types.js';
import { WolverineTrustLedger } from '../trust_network/ledger.js';
import { TrustConsensusEngine } from '../trust_network/consensus.js';
import { PortableTrustProofGenerator } from '../trust_network/proof.js';
import { INetworkTransport } from './network_transport.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export class TrustGatewayServer {
  public readonly config: TrustGatewayConfig;
  private transport: INetworkTransport;
  private ledger: WolverineTrustLedger;
  private consensusEngine: TrustConsensusEngine;
  private tenants = new Map<
    string,
    { tenantId: string; customerPubkey: Buffer; databases: Set<string>; tier: string }
  >();
  private validatorKeys = new Map<string, Buffer>();
  private isOnline: boolean = true;

  constructor(config: TrustGatewayConfig, transport: INetworkTransport) {
    this.config = config;
    this.transport = transport;
    this.ledger = new WolverineTrustLedger();
    this.consensusEngine = new TrustConsensusEngine(
      this.ledger,
      config.requiredQuorum,
      config.totalValidators
    );
  }

  public registerTenant(
    tenantId: string,
    customerPubkey: Buffer,
    databaseId: string,
    tier: string = 'ENTERPRISE'
  ): void {
    const existing = this.tenants.get(tenantId);
    if (existing) {
      existing.databases.add(databaseId);
    } else {
      this.tenants.set(tenantId, {
        tenantId,
        customerPubkey,
        databases: new Set([databaseId]),
        tier,
      });
    }
  }

  public registerValidatorKey(validatorId: string, publicKey: Buffer): void {
    this.validatorKeys.set(validatorId, publicKey);
    this.consensusEngine.registerValidatorKey(validatorId, publicKey);
  }

  public setOnlineStatus(isOnline: boolean): void {
    this.isOnline = isOnline;
  }

  public async ingestCommitment(commitment: TrustCommitment): Promise<{
    certificate: QuorumCertificate;
    proof: PortableTrustProof;
    ledgerRecord: TrustLedgerRecord;
  }> {
    if (!this.isOnline) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_UNAVAILABLE,
        'Trust Gateway is offline / unreachable'
      );
    }

    const tenant = this.tenants.get(commitment.tenantId);
    if (!tenant) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Unregistered tenant: ${commitment.tenantId}`
      );
    }

    if (!tenant.databases.has(commitment.databaseId)) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Database ${commitment.databaseId} is not registered for tenant ${commitment.tenantId}`
      );
    }

    // 1. Dispatch Attestation Requests in Parallel across Validator Cluster
    const attestPromises = this.config.validatorEndpoints.map(async (v) => {
      try {
        const response: AttestRpcResponse = await this.transport.sendAttestRpc(v.endpoint, {
          commitment,
          tenantPubkeyHex: tenant.customerPubkey.toString('hex'),
        });
        return response.success && response.attestation ? response.attestation : null;
      } catch {
        return null;
      }
    });

    const attestResults = await Promise.all(attestPromises);
    const validAttestations = attestResults.filter((a): a is NonNullable<typeof a> => a !== null);

    // 2. Execute Quorum Consensus
    const certificate = this.consensusEngine.processAttestations(commitment, validAttestations);

    // 3. Obtain Master Ledger Record
    const records = this.ledger.getRecords();
    const ledgerRecord = records[records.length - 1]!;

    // 4. Broadcast to Ledger Replicas
    const replicatePromises = this.config.replicaEndpoints.map(async (r) => {
      try {
        await this.transport.sendReplicateRpc(r.endpoint, { record: ledgerRecord });
      } catch {
        // Replica failure handled gracefully
      }
    });
    await Promise.all(replicatePromises);

    // 5. Generate Standalone Portable Proof
    const proof = PortableTrustProofGenerator.generateProof(
      commitment,
      certificate,
      ledgerRecord,
      this.validatorKeys
    );

    return {
      certificate,
      proof,
      ledgerRecord,
    };
  }

  public getLedger(): WolverineTrustLedger {
    return this.ledger;
  }
}
