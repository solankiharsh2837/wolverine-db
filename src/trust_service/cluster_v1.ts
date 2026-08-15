import {
  TrustCommitment,
  QuorumCertificate,
  PortableTrustProof,
  TrustLedgerRecord,
} from '../trust_network/types.js';
import { PersistentTrustLedger } from './persistent_ledger.js';
import { ByzantineTrustValidator } from './byzantine_validator.js';
import { BftConsensusEngine } from './bft_consensus_engine.js';
import { PortableTrustProofGenerator } from '../trust_network/proof.js';
import { MaliciousGatewaySimulator } from './malicious_gateway_simulator.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface ProductionClusterOptions {
  totalValidators?: number;
  requiredQuorum?: number;
}

export class WolverineProductionCluster {
  public readonly ledger: PersistentTrustLedger;
  public readonly consensusEngine: BftConsensusEngine;
  public readonly validators = new Map<string, ByzantineTrustValidator>();
  public readonly adversarySimulator: MaliciousGatewaySimulator;
  private tenants = new Map<
    string,
    { tenantId: string; customerPubkey: Buffer; databases: Set<string>; tier: string }
  >();
  private validatorKeys = new Map<string, Buffer>();
  private isGatewayOnline: boolean = true;

  constructor(options: ProductionClusterOptions = {}) {
    const totalValidators = options.totalValidators ?? 5;
    const requiredQuorum = options.requiredQuorum ?? 4; // M = 4 for N = 5

    this.ledger = new PersistentTrustLedger();
    this.consensusEngine = new BftConsensusEngine(this.ledger, totalValidators, requiredQuorum);

    for (let i = 1; i <= totalValidators; i++) {
      const vId = `val-0${i}`;
      const validator = new ByzantineTrustValidator({
        validatorId: vId,
        validatorSetId: 'valset-prod-v1',
        epoch: 1,
        port: 9200 + i,
        host: '127.0.0.1',
      });
      this.validators.set(vId, validator);
      this.validatorKeys.set(vId, validator.publicKey);
      this.consensusEngine.registerValidatorKey(vId, validator.publicKey);
    }

    this.adversarySimulator = new MaliciousGatewaySimulator(this.validators, this.consensusEngine);
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

  public setGatewayOnline(isOnline: boolean): void {
    this.isGatewayOnline = isOnline;
  }

  public async submitCommitment(commitment: TrustCommitment): Promise<{
    certificate: QuorumCertificate;
    proof: PortableTrustProof;
    ledgerRecord: TrustLedgerRecord;
  }> {
    if (!this.isGatewayOnline) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_UNAVAILABLE,
        'Wolverine Gateway is offline / dead'
      );
    }

    const tenant = this.tenants.get(commitment.tenantId);
    if (!tenant) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Unregistered tenant: ${commitment.tenantId}`
      );
    }

    // 1. Dispatch in parallel to all 5 Byzantine Validators
    const attestations = [];
    const rejectionErrors: WolverineError[] = [];

    for (const val of this.validators.values()) {
      try {
        const att = val.attestCommitment(commitment, tenant.customerPubkey);
        attestations.push(att);
      } catch (err: any) {
        if (err instanceof WolverineError) {
          rejectionErrors.push(err);
        }
      }
    }

    if (attestations.length === 0 && rejectionErrors.length > 0) {
      throw rejectionErrors[0]!;
    }

    // 2. Execute BFT Quorum Consensus (Requires M=4 of N=5)
    const certificate = await this.consensusEngine.processAttestations(commitment, attestations);

    // 3. Obtain Master Ledger Record
    const records = this.ledger.getRecords();
    const ledgerRecord = records[records.length - 1]!;

    // 4. Generate Standalone Portable Proof
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
}
