import http from 'node:http';
import { MtlsServer, MtlsClient } from '../network/mtls_transport.js';
import { ValidatorSetManager } from '../trust/validator_set.js';
import {
  CanonicalQuorumCertificate,
  QuorumAggregator,
} from '../trust/quorum_certificate.js';
import { CanonicalCommitment } from '../trust/commitment.js';
import { ValidatorAttestation } from '../trust/validator_state_machine.js';

export interface GatewayDaemonConfig {
  port: number;
  host?: string;
  tlsCertPem: string;
  tlsPrivPem: string;
  caPem: string;
  validatorEndpoints: { validatorId: string; url: string }[];
  validatorSetManager: ValidatorSetManager;
}

export class WdbGatewayDaemon {
  private config: GatewayDaemonConfig;
  private server: MtlsServer;
  private mtlsClient: MtlsClient;
  private receipts = new Map<string, CanonicalQuorumCertificate>();

  constructor(config: GatewayDaemonConfig) {
    this.config = config;

    this.server = new MtlsServer({
      port: config.port,
      host: config.host || '127.0.0.1',
      certPem: config.tlsCertPem,
      privPem: config.tlsPrivPem,
      caPem: config.caPem,
      requestHandler: this.handleRequest.bind(this),
    });

    this.mtlsClient = new MtlsClient({
      certPem: config.tlsCertPem,
      privPem: config.tlsPrivPem,
      caPem: config.caPem,
      rejectUnauthorized: true,
    });
  }

  public async start(): Promise<number> {
    return this.server.start();
  }

  public get boundPort(): number {
    return this.server.boundPort;
  }

  public async stop(): Promise<void> {
    await this.server.stop();
  }

  public getReceipt(commitSeq: bigint): CanonicalQuorumCertificate | undefined {
    return this.receipts.get(commitSeq.toString());
  }

  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = req.url || '/';
    const method = req.method || 'GET';

    if (url === '/v1/health' && method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'OK',
          role: 'gateway',
          validatorEndpointsCount: this.config.validatorEndpoints.length,
          cachedReceiptsCount: this.receipts.size,
        })
      );
      return;
    }

    if (url.startsWith('/v1/receipts/') && method === 'GET') {
      const seqStr = url.replace('/v1/receipts/', '');
      const cert = this.receipts.get(seqStr);
      if (cert) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            ...cert,
            commitSeq: cert.commitSeq.toString(),
            finalizedAtUs: cert.finalizedAtUs.toString(),
            attestations: cert.attestations.map((a) => ({
              ...a,
              commitSeq: a.commitSeq.toString(),
              attestationTimestampUs: a.attestationTimestampUs.toString(),
            })),
          })
        );
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Receipt not found for sequence ${seqStr}` }));
      }
      return;
    }

    if (url === '/v1/commitments' && method === 'POST') {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', async () => {
        try {
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

          // Broadcast commitment to all validator endpoints over mTLS
          const attestPromises = this.config.validatorEndpoints.map(async (valEndpoint) => {
            try {
              const r = await this.mtlsClient.request<{
                validatorId: string;
                commitmentId: string;
                commitmentDigestHex: string;
                epoch: number;
                commitSeq: string;
                attestationTimestampUs: string;
                signatureHex: string;
              }>(`${valEndpoint.url}/v1/attest`, 'POST', rawCmt, 3000);

              if (r.statusCode === 200 && r.data?.signatureHex) {
                const att: ValidatorAttestation = {
                  validatorId: r.data.validatorId,
                  commitmentId: r.data.commitmentId,
                  commitmentDigestHex: r.data.commitmentDigestHex,
                  epoch: r.data.epoch,
                  commitSeq: BigInt(r.data.commitSeq),
                  attestationTimestampUs: BigInt(r.data.attestationTimestampUs),
                  signatureHex: r.data.signatureHex,
                };
                return att;
              }
              return null;
            } catch {
              return null;
            }
          });

          const results = await Promise.all(attestPromises);
          const validAttestations = results.filter((a): a is ValidatorAttestation => a !== null);

          // Aggregate Quorum Certificate
          const qc = QuorumAggregator.aggregate(
            commitment,
            validAttestations,
            this.config.validatorSetManager
          );

          this.receipts.set(commitment.commitSeq.toString(), qc);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              ...qc,
              commitSeq: qc.commitSeq.toString(),
              finalizedAtUs: qc.finalizedAtUs.toString(),
              attestations: qc.attestations.map((a) => ({
                ...a,
                commitSeq: a.commitSeq.toString(),
                attestationTimestampUs: a.attestationTimestampUs.toString(),
              })),
            })
          );
        } catch (err: any) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: err.message || 'CONSENSUS_UNAVAILABLE',
              code: err.code || 'CONSENSUS_UNAVAILABLE',
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
