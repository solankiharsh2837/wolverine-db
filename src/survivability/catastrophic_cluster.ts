import {
  TrustCommitment,
  QuorumCertificate,
  PortableTrustProof,
} from '../trust_network/types.js';
import { ImmutableTrustReceipt } from '../bft_hardening/types.js';
import { PersistentTrustLedger } from '../trust_service/persistent_ledger.js';
import { ByzantineTrustValidator } from '../trust_service/byzantine_validator.js';
import { BftConsensusEngine } from '../trust_service/bft_consensus_engine.js';
import { PortableTrustProofGenerator } from '../trust_network/proof.js';
import { ImmutableTrustReceiptGenerator } from '../trust_receipt/receipt.js';
import { CrashSafeValidatorJournal } from './crash_safe_journal.js';
import { ReceiptChain } from './receipt_chain.js';
import { CustomerDisasterSlaManager } from './customer_sla_manager.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export class CatastrophicSurvivabilityCluster {
  public ledger: PersistentTrustLedger;
  public consensusEngine: BftConsensusEngine;
  public validators = new Map<
    string,
    { validator: ByzantineTrustValidator; journal: CrashSafeValidatorJournal; isOnline: boolean }
  >();
  public receiptChain = new ReceiptChain();
  public customerSla = new CustomerDisasterSlaManager();
  private validatorKeys = new Map<string, Buffer>();
  private activeTenants = new Map<string, { customerPubkey: Buffer; databaseId: string }>();
  public currentEpoch: number = 1;
  public isGatewayOnline: boolean = true;

  constructor(totalValidators: number = 5, requiredQuorum: number = 4) {
    this.ledger = new PersistentTrustLedger();
    this.consensusEngine = new BftConsensusEngine(this.ledger, totalValidators, requiredQuorum);

    for (let i = 1; i <= totalValidators; i++) {
      const vId = `val-0${i}`;
      const validator = new ByzantineTrustValidator({
        validatorId: vId,
        validatorSetId: `valset-epoch-1`,
        epoch: 1,
        port: 9500 + i,
        host: '127.0.0.1',
      });
      const journal = new CrashSafeValidatorJournal(vId);

      this.validators.set(vId, { validator, journal, isOnline: true });
      this.validatorKeys.set(vId, validator.publicKey);
      this.consensusEngine.registerValidatorKey(vId, validator.publicKey);
    }
  }

  public registerTenant(tenantId: string, customerPubkey: Buffer, databaseId: string): void {
    this.activeTenants.set(tenantId, { customerPubkey, databaseId });
  }

  public async submitCommitment(commitment: TrustCommitment): Promise<{
    certificate: QuorumCertificate;
    proof: PortableTrustProof;
    receipt: ImmutableTrustReceipt;
  }> {
    if (!this.isGatewayOnline) {
      this.customerSla.queueCommitment(commitment);
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_UNAVAILABLE,
        'Wolverine Gateway is DESTROYED / OFFLINE'
      );
    }

    const tenant = this.activeTenants.get(commitment.tenantId);
    if (!tenant) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        `Unregistered tenant: ${commitment.tenantId}`
      );
    }

    const attestations = [];
    for (const entry of this.validators.values()) {
      if (entry.isOnline) {
        try {
          const att = entry.validator.attestCommitment(commitment, tenant.customerPubkey);
          entry.journal.append(
            this.currentEpoch,
            commitment.commitSeq,
            commitment.checkpointDigest,
            this.ledger.getStateRootSnapshot().chainHeadDigest,
            att.observedCommitmentDigest,
            this.ledger.getMerkleStateRoot(),
            Buffer.alloc(32, 1)
          );
          attestations.push(att);
        } catch {
          // Rejection handled by consensus engine
        }
      }
    }

    const certificate = await this.consensusEngine.processAttestations(commitment, attestations);
    const records = this.ledger.getRecords();
    const ledgerRecord = records[records.length - 1]!;

    const proof = PortableTrustProofGenerator.generateProof(
      commitment,
      certificate,
      ledgerRecord,
      this.validatorKeys
    );

    const merkleRoot = this.ledger.getMerkleStateRoot();
    const receipt = ImmutableTrustReceiptGenerator.generateReceipt(proof, merkleRoot);
    this.receiptChain.appendReceipt(receipt);
    this.customerSla.recordFinalized(commitment.commitSeq, ledgerRecord.ledgerSeq);

    return {
      certificate,
      proof,
      receipt,
    };
  }

  public simulateDisaster(params: {
    destroyGateway?: boolean;
    destroyValidators?: string[];
  }): void {
    if (params.destroyGateway) {
      this.isGatewayOnline = false;
      this.customerSla.setWolverineOnline(false, 'CATASTROPHIC_PARTIAL_LOSS');
    }

    if (params.destroyValidators) {
      for (const vId of params.destroyValidators) {
        const v = this.validators.get(vId);
        if (v) {
          v.isOnline = false;
        }
      }
    }
  }

  public async restoreAndAdvanceEpoch(newEpoch: number, newValidatorSetId: string): Promise<void> {
    this.currentEpoch = newEpoch;
    this.isGatewayOnline = true;
    this.customerSla.setWolverineOnline(true, 'HEALTHY');

    // Replace destroyed validators with healthy replacements & update surviving validators
    for (let i = 1; i <= 5; i++) {
      const vId = `val-0${i}`;
      const entry = this.validators.get(vId);
      if (entry) {
        if (!entry.isOnline) {
          const newValidator = new ByzantineTrustValidator({
            validatorId: vId,
            validatorSetId: newValidatorSetId,
            epoch: newEpoch,
            port: 9500 + i,
            host: '127.0.0.1',
          });
          entry.validator = newValidator;
          entry.isOnline = true;
          this.validatorKeys.set(vId, newValidator.publicKey);
          this.consensusEngine.registerValidatorKey(vId, newValidator.publicKey);
        } else {
          (entry.validator as any).config.epoch = newEpoch;
          (entry.validator as any).config.validatorSetId = newValidatorSetId;
        }
      }
    }
  }

  public async replayQueuedCustomerCommitments(): Promise<ImmutableTrustReceipt[]> {
    const queued = this.customerSla.getQueuedCommitments();
    const receipts: ImmutableTrustReceipt[] = [];

    for (const cmt of queued) {
      const res = await this.submitCommitment(cmt);
      receipts.push(res.receipt);
    }

    return receipts;
  }
}
