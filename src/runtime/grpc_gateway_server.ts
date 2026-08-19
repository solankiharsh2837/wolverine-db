import * as http2 from 'node:http2';
import { TrustGatewayServer } from './gateway.js';
import { TlsConfig, replacer, reviver } from './grpc_transport.js';
import { TrustCommitment, PortableTrustProof, QuorumCertificate, TrustLedgerRecord } from '../trust_network/types.js';
import { ImmutableTrustReceipt } from '../bft_hardening/types.js';
import { ImmutableTrustReceiptGenerator } from '../trust_receipt/receipt.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface GatewayIngestionRequest {
  commitment: TrustCommitment;
}

export interface GatewayIngestionResponse {
  success: boolean;
  commitmentId?: string;
  receipt?: ImmutableTrustReceipt;
  proof?: PortableTrustProof;
  error?: string;
}

export interface GatewayStatusResponse {
  gatewayId: string;
  isOnline: boolean;
  ledgerHeadSeq: string;
}

/**
 * Customer-facing HTTP/2 server that exposes the Trust Gateway as a network service.
 * Accepts TrustCommitment submissions over HTTP/2 POST to /ingest and returns
 * trust receipts with portable proofs.
 *
 * This is the production replacement for the in-process gateway reference used in tests.
 */
export class GrpcGatewayServer {
  private server: http2.Http2Server | http2.Http2SecureServer;
  private readonly gateway: TrustGatewayServer;

  constructor(
    gateway: TrustGatewayServer,
    tlsConfig?: TlsConfig
  ) {
    this.gateway = gateway;

    if (tlsConfig) {
      this.server = http2.createSecureServer({
        cert: tlsConfig.cert,
        key: tlsConfig.key,
        ca: tlsConfig.ca,
        rejectUnauthorized: true,
      });
    } else {
      this.server = http2.createServer();
    }

    this.server.on('stream', (stream, headers) => {
      const path = headers[http2.constants.HTTP2_HEADER_PATH] as string;
      const method = headers[http2.constants.HTTP2_HEADER_METHOD] as string;

      if (path === '/ingest' && method === 'POST') {
        this.handleIngest(stream);
      } else if (path === '/status' && method === 'GET') {
        this.handleStatus(stream);
      } else if (path === '/health' && method === 'GET') {
        this.handleHealth(stream);
      } else {
        stream.respond({ [http2.constants.HTTP2_HEADER_STATUS]: 404 });
        stream.end(JSON.stringify({ error: 'Not Found' }));
      }
    });
  }

  private handleIngest(stream: http2.ServerHttp2Stream): void {
    let data = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      data += chunk;
    });
    stream.on('end', async () => {
      try {
        const req = JSON.parse(data, reviver) as GatewayIngestionRequest;

        if (!req.commitment || !req.commitment.commitmentId) {
          stream.respond({
            [http2.constants.HTTP2_HEADER_STATUS]: 400,
            [http2.constants.HTTP2_HEADER_CONTENT_TYPE]: 'application/json',
          });
          stream.end(JSON.stringify({ success: false, error: 'Missing or malformed commitment' }, replacer));
          return;
        }

        const result = await this.gateway.ingestCommitment(req.commitment);

        // Generate commercial immutable trust receipt
        const receipt = ImmutableTrustReceiptGenerator.generateReceipt(
          result.proof,
          result.ledgerRecord.recordDigest
        );

        const response: GatewayIngestionResponse = {
          success: true,
          commitmentId: req.commitment.commitmentId,
          receipt,
          proof: result.proof,
        };

        stream.respond({
          [http2.constants.HTTP2_HEADER_STATUS]: 200,
          [http2.constants.HTTP2_HEADER_CONTENT_TYPE]: 'application/json',
        });
        stream.end(JSON.stringify(response, replacer));
      } catch (err: any) {
        const status = err instanceof WolverineError ? 422 : 500;
        stream.respond({
          [http2.constants.HTTP2_HEADER_STATUS]: status,
          [http2.constants.HTTP2_HEADER_CONTENT_TYPE]: 'application/json',
        });
        stream.end(JSON.stringify({
          success: false,
          error: err.message ?? 'Internal gateway error',
        }, replacer));
      }
    });
  }

  private handleStatus(stream: http2.ServerHttp2Stream): void {
    const ledger = this.gateway.getLedger();
    const response: GatewayStatusResponse = {
      gatewayId: this.gateway.gatewayId,
      isOnline: true,
      ledgerHeadSeq: ledger.getCurrentSequence().toString(),
    };
    stream.respond({
      [http2.constants.HTTP2_HEADER_STATUS]: 200,
      [http2.constants.HTTP2_HEADER_CONTENT_TYPE]: 'application/json',
    });
    stream.end(JSON.stringify(response, replacer));
  }

  private handleHealth(stream: http2.ServerHttp2Stream): void {
    stream.respond({
      [http2.constants.HTTP2_HEADER_STATUS]: 200,
      [http2.constants.HTTP2_HEADER_CONTENT_TYPE]: 'application/json',
    });
    stream.end(JSON.stringify({ status: 'healthy' }));
  }

  public listen(port: number, host: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.on('error', reject);
      this.server.listen(port, host, () => {
        this.server.off('error', reject);
        resolve();
      });
    });
  }

  public close(): Promise<void> {
    return new Promise((resolve) => {
      this.server.close(() => {
        resolve();
      });
    });
  }

  public getGateway(): TrustGatewayServer {
    return this.gateway;
  }
}
