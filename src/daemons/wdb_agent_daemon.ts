import crypto from 'node:crypto';
import { MtlsClient } from '../network/mtls_transport.js';
import { ICustomerSigner } from '../crypto/customer_signer.js';
import { DeterministicStateFrontier } from '../evidence/state_frontier.js';
import { DurableEvidenceJournal } from '../evidence/journal.js';
import {
  CanonicalCommitment,
  computeCanonicalCommitmentDigest,
  computeAgentAttestationDigest,
} from '../trust/commitment.js';
import { CanonicalQuorumCertificate } from '../trust/quorum_certificate.js';
import { BootstrapSnapshot } from '../evidence/types.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface AgentDaemonConfig {
  agentNodeId: string;
  tenantId: string;
  databaseId: string;
  tlsCertPem: string;
  tlsPrivPem: string;
  caPem: string;
  gatewayUrl: string;
  agentPrivKey: crypto.KeyObject;
  customerSigner: ICustomerSigner;
  journalPath?: string;
  epoch?: number;
}

export class WdbAgentDaemon {
  public readonly agentNodeId: string;
  private config: AgentDaemonConfig;
  private mtlsClient: MtlsClient;
  private frontier: DeterministicStateFrontier;
  private journal?: DurableEvidenceJournal;
  private agentPubkey: Buffer;
  private commitSequence: bigint = 0n;
  private lastCommitmentDigestHex: string = '0000000000000000000000000000000000000000000000000000000000000000';

  constructor(config: AgentDaemonConfig) {
    this.agentNodeId = config.agentNodeId;
    this.config = config;

    const pubKeyObj = crypto.createPublicKey(config.agentPrivKey);
    this.agentPubkey = pubKeyObj.export({ format: 'der', type: 'spki' });

    this.frontier = new DeterministicStateFrontier(config.epoch || 1);

    if (config.journalPath) {
      this.journal = new DurableEvidenceJournal(config.journalPath);
    }

    this.mtlsClient = new MtlsClient({
      certPem: config.tlsCertPem,
      privPem: config.tlsPrivPem,
      caPem: config.caPem,
      rejectUnauthorized: true,
    });
  }

  public get sequence(): bigint {
    return this.commitSequence;
  }

  public get stateFrontier(): DeterministicStateFrontier {
    return this.frontier;
  }

  public bootstrap(snapshot: BootstrapSnapshot): void {
    this.frontier.bootstrap(snapshot);
  }

  /**
   * Constructs, dual-signs, and dispatches a commitment to the Gateway over mTLS.
   */
  public async commitAndWitness(
    checkpointDigestHex: string,
    stateMerkleRootHex: string,
    changeChainHeadHex: string,
    lsn: string
  ): Promise<CanonicalQuorumCertificate> {
    this.commitSequence++;
    const seq = this.commitSequence;
    const timestampUs = BigInt(Date.now()) * 1000n;
    const epoch = this.frontier.schemaEpoch;

    const unsigned = {
      commitmentId: `cmt-${this.config.tenantId}-${seq}`,
      tenantId: this.config.tenantId,
      databaseId: this.config.databaseId,
      epoch,
      commitSeq: seq.toString(),
      checkpointDigestHex,
      stateMerkleRootHex,
      changeChainHeadHex,
      logicalTimestampUs: timestampUs.toString(),
      lsn,
      previousCommitmentDigestHex: this.lastCommitmentDigestHex,
    };

    const commitmentDigest = computeCanonicalCommitmentDigest(unsigned);

    // 1. Enclave Agent Signature (Digest || LSN)
    const agentDigest = computeAgentAttestationDigest(commitmentDigest, lsn);
    const agentSig = crypto.sign(null, agentDigest, this.config.agentPrivKey);

    // 2. Customer Authority Signature (via fail-closed KMS client)
    const custSig = await this.config.customerSigner.signCommitment(commitmentDigest, seq);

    const fullCommitment: CanonicalCommitment = {
      ...unsigned,
      commitSeq: seq,
      logicalTimestampUs: timestampUs,
      agentAttestation: {
        agentNodeId: this.agentNodeId,
        agentPubkeyHex: this.agentPubkey.toString('hex'),
        signatureHex: agentSig.toString('hex'),
        lsn,
      },
      customerAuthorization: {
        keyId: this.config.customerSigner.keyId,
        customerPubkeyHex: this.config.customerSigner.publicKey.toString('hex'),
        signatureHex: custSig.toString('hex'),
        commitSeq: seq,
      },
    };

    // Serialize payload for mTLS POST
    const serializablePayload = {
      ...fullCommitment,
      commitSeq: fullCommitment.commitSeq.toString(),
      logicalTimestampUs: fullCommitment.logicalTimestampUs.toString(),
      customerAuthorization: {
        ...fullCommitment.customerAuthorization,
        commitSeq: fullCommitment.customerAuthorization.commitSeq.toString(),
      },
    };

    // 3. Dispatch to Gateway over mTLS
    const response = await this.mtlsClient.request<any>(
      `${this.config.gatewayUrl}/v1/commitments`,
      'POST',
      serializablePayload,
      5000
    );

    if (response.statusCode !== 200 || !response.data?.certificateDigestHex) {
      throw new WolverineError(
        WolverineErrorCode.ANCHOR_VERIFICATION_FAILED,
        `Gateway failed to achieve quorum for sequence ${seq}: ${response.data?.error || response.statusCode}`
      );
    }

    const qc: CanonicalQuorumCertificate = {
      ...response.data,
      commitSeq: BigInt(response.data.commitSeq),
      finalizedAtUs: BigInt(response.data.finalizedAtUs),
      attestations: response.data.attestations.map((a: any) => ({
        ...a,
        commitSeq: BigInt(a.commitSeq),
        attestationTimestampUs: BigInt(a.attestationTimestampUs),
      })),
    };

    this.lastCommitmentDigestHex = commitmentDigest.toString('hex');
    return qc;
  }

  public async close(): Promise<void> {
    if (this.journal) {
      await this.journal.close();
    }
  }
}
