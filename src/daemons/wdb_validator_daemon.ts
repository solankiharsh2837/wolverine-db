import http from 'node:http';
import crypto from 'node:crypto';
import { MtlsServer } from '../network/mtls_transport.js';
import {
  FormalValidatorStateMachine,
  ValidatorAttestation,
} from '../trust/validator_state_machine.js';
import { ValidatorSetManager } from '../trust/validator_set.js';
import { ValidatorDurableJournal } from '../trust/validator_journal.js';
import { CanonicalCommitment } from '../trust/commitment.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export type ByzantineMode = 'NONE' | 'DOUBLE_SIGN' | 'WRONG_DIGEST' | 'WRONG_SEQUENCE' | 'DELAY' | 'DROP';

export interface ValidatorDaemonConfig {
  validatorId: string;
  port: number;
  host?: string;
  tlsCertPem: string;
  tlsPrivPem: string;
  caPem: string;
  ed25519PrivKey: crypto.KeyObject;
  validatorSetManager: ValidatorSetManager;
  journalPath?: string;
  expectedAgentPubkey?: Buffer;
  expectedCustomerPubkey?: Buffer;
  byzantineMode?: ByzantineMode;
}

export class WdbValidatorDaemon {
  public readonly validatorId: string;
  private config: ValidatorDaemonConfig;
  private stateMachine: FormalValidatorStateMachine;
  private journal?: ValidatorDurableJournal;
  private server: MtlsServer;
  private byzantineMode: ByzantineMode;

  constructor(config: ValidatorDaemonConfig) {
    this.validatorId = config.validatorId;
    this.config = config;
    this.byzantineMode = config.byzantineMode || 'NONE';

    if (config.journalPath) {
      this.journal = new ValidatorDurableJournal(config.validatorId, config.journalPath);
    }

    this.stateMachine = new FormalValidatorStateMachine(
      config.validatorId,
      config.ed25519PrivKey,
      config.validatorSetManager,
      this.journal,
      config.expectedAgentPubkey,
      config.expectedCustomerPubkey
    );

    this.server = new MtlsServer({
      port: config.port,
      host: config.host || '127.0.0.1',
      certPem: config.tlsCertPem,
      privPem: config.tlsPrivPem,
      caPem: config.caPem,
      requestHandler: this.handleRequest.bind(this),
    });
  }

  public setByzantineMode(mode: ByzantineMode): void {
    this.byzantineMode = mode;
  }

  public async start(): Promise<number> {
    await this.stateMachine.initialize();
    return this.server.start();
  }

  public get boundPort(): number {
    return this.server.boundPort;
  }

  public async stop(): Promise<void> {
    await this.server.stop();
    if (this.journal) {
      await this.journal.close();
    }
  }

  public getStateMachine(): FormalValidatorStateMachine {
    return this.stateMachine;
  }

  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = req.url || '/';
    const method = req.method || 'GET';

    if (url === '/v1/health' && method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'OK',
          validatorId: this.validatorId,
          lifecycleState: this.stateMachine.lifecycleState,
          sequence: this.stateMachine.sequence.toString(),
          lastDigest: this.stateMachine.lastDigest,
          byzantineMode: this.byzantineMode,
        })
      );
      return;
    }

    if (url === '/v1/attest' && method === 'POST') {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', async () => {
        try {
          if (this.byzantineMode === 'DROP') {
            res.writeHead(503, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'BYZANTINE_DROP: Validator deliberately dropped request' }));
            return;
          }

          if (this.byzantineMode === 'DELAY') {
            await new Promise((r) => setTimeout(r, 100));
          }

          const rawCmt = JSON.parse(body);
          const commitment: CanonicalCommitment = {
            ...rawCmt,
            commitSeq: BigInt(rawCmt.commitSeq),
            logicalTimestampUs: BigInt(rawCmt.logicalTimestampUs),
            customerAuthorization: {
              ...rawCmt.customerAuthorization,
              commitSeq: BigInt(rawCmt.customerAuthorization.commitSeq),
            },
          };

          if (this.byzantineMode === 'WRONG_DIGEST') {
            // Malicious Byzantine behavior: Sign forged digest
            const forgedDigest = crypto.createHash('sha256').update('BYZANTINE_ATTACK_PAYLOAD').digest();
            const attDigest = this.stateMachine.computeAttestationDigest(
              forgedDigest,
              commitment.epoch,
              commitment.commitSeq,
              BigInt(Date.now()) * 1000n
            );
            const sig = crypto.sign(null, attDigest, this.config.ed25519PrivKey);
            const att: ValidatorAttestation = {
              validatorId: this.validatorId,
              commitmentId: commitment.commitmentId,
              commitmentDigestHex: forgedDigest.toString('hex'),
              epoch: commitment.epoch,
              commitSeq: commitment.commitSeq,
              attestationTimestampUs: BigInt(Date.now()) * 1000n,
              signatureHex: sig.toString('hex'),
            };
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                ...att,
                commitSeq: att.commitSeq.toString(),
                attestationTimestampUs: att.attestationTimestampUs.toString(),
              })
            );
            return;
          }

          const attestation = await this.stateMachine.attestCommitment(commitment);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              ...attestation,
              commitSeq: attestation.commitSeq.toString(),
              attestationTimestampUs: attestation.attestationTimestampUs.toString(),
            })
          );
        } catch (err: any) {
          const statusCode = err.code === WolverineErrorCode.HISTORY_MUTATION_DETECTED ? 409 : 400;
          res.writeHead(statusCode, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: err.message,
              code: err.code || 'UNKNOWN_ERROR',
            })
          );
        }
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  }
}
