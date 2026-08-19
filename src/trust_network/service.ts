import {
  TrustCommitment,
  QuorumCertificate,
  PortableTrustProof,
  TrustLedgerRecord,
} from './types.js';
import { verifyCustomerCommitment } from './commitment.js';
import { WolverineTrustLedger } from './ledger.js';
import { TrustValidator } from './validator.js';
import { TrustConsensusEngine } from './consensus.js';
import { PortableTrustProofGenerator } from './proof.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface TenantRegistration {
  tenantId: string;
  customerPubkey: Buffer;
  databases: Set<string>;
  tier: 'FREE' | 'PRO' | 'BUSINESS' | 'ENTERPRISE';
  maxCommitmentsPerDay: number;
  commitmentsUsedToday: number;
}

export class WolverineTrustNetworkService {
  private ledger: WolverineTrustLedger;
  private consensusEngine: TrustConsensusEngine;
  private validators = new Map<string, TrustValidator>();
  private tenants = new Map<string, TenantRegistration>();

  // Storage for finalized certificates and proofs: checkpointId -> { certificate, proof, ledgerRecord }
  private finalizedRecords = new Map<
    string,
    {
      commitment: TrustCommitment;
      certificate: QuorumCertificate;
      ledgerRecord: TrustLedgerRecord;
      proof: PortableTrustProof;
    }
  >();

  private isOnline: boolean = true;

  constructor(
    requiredQuorum: number = 3,
    totalValidators: number = 5
  ) {
    this.ledger = new WolverineTrustLedger();
    this.consensusEngine = new TrustConsensusEngine(this.ledger, requiredQuorum, totalValidators);

    // Provision default validator set
    for (let i = 1; i <= totalValidators; i++) {
      const vId = `val-0${i}`;
      const validator = new TrustValidator(vId);
      this.validators.set(vId, validator);
      this.consensusEngine.registerValidatorKey(vId, validator.publicKey);
    }
  }

  public registerTenant(
    tenantId: string,
    customerPubkey: Buffer,
    databaseId: string,
    tier: 'FREE' | 'PRO' | 'BUSINESS' | 'ENTERPRISE' = 'ENTERPRISE'
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
        maxCommitmentsPerDay: 100000,
        commitmentsUsedToday: 0,
      });
    }
  }

  public setNetworkOnlineStatus(status: boolean): void {
    this.isOnline = status;
  }

  public async submitCommitment(commitment: TrustCommitment): Promise<{
    status: 'FINALIZED' | 'QUEUED';
    certificate: QuorumCertificate;
    proof: PortableTrustProof;
  }> {
    if (!this.isOnline) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_UNAVAILABLE,
        'Wolverine Trust Network is temporarily offline / unreachable'
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

    // Cryptographically authenticate customer commitment signature at ingress
    if (!verifyCustomerCommitment(commitment, tenant.customerPubkey)) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Invalid commitment signature or customer public key mismatch for tenant ${commitment.tenantId}`
      );
    }

    // 1. Broadcast to Validators and Collect Attestations
    const attestations = [];
    const rejectionErrors: WolverineError[] = [];

    for (const val of this.validators.values()) {
      try {
        const att = val.attestCommitment(commitment, tenant.customerPubkey);
        attestations.push(att);
      } catch (err) {
        if (err instanceof WolverineError) {
          rejectionErrors.push(err);
        }
      }
    }

    // If all validators explicitly rejected due to history/auth violation, throw that error
    if (attestations.length === 0 && rejectionErrors.length > 0) {
      throw rejectionErrors[0]!;
    }

    // 2. Execute Consensus
    const certificate = this.consensusEngine.processAttestations(commitment, attestations);

    // 3. Obtain Ledger Finalization Record
    const records = this.ledger.getRecords();
    const ledgerRecord = records[records.length - 1]!;

    // 4. Generate Portable Proof
    const valKeyMap = new Map<string, Buffer>();
    for (const [id, v] of this.validators.entries()) {
      valKeyMap.set(id, v.publicKey);
    }

    const proof = PortableTrustProofGenerator.generateProof(
      commitment,
      certificate,
      ledgerRecord,
      valKeyMap
    );

    this.finalizedRecords.set(commitment.checkpointId, {
      commitment,
      certificate,
      ledgerRecord,
      proof,
    });

    tenant.commitmentsUsedToday++;

    return {
      status: 'FINALIZED',
      certificate,
      proof,
    };
  }

  public getPortableProof(checkpointId: string): PortableTrustProof | null {
    const item = this.finalizedRecords.get(checkpointId);
    return item ? item.proof : null;
  }

  public getValidators(): Map<string, Buffer> {
    const keys = new Map<string, Buffer>();
    for (const [id, val] of this.validators.entries()) {
      keys.set(id, val.publicKey);
    }
    return keys;
  }

  public getLedger(): WolverineTrustLedger {
    return this.ledger;
  }
}
