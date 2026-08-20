import * as http2 from 'node:http2';
import { TrustGatewayServer } from './gateway.js';
import { TlsConfig, replacer, reviver } from './grpc_transport.js';
import { TrustCommitment, PortableTrustProof, QuorumCertificate, TrustLedgerRecord } from '../trust_network/types.js';
import { ImmutableTrustReceipt } from '../bft_hardening/types.js';
import { ImmutableTrustReceiptGenerator } from '../trust_receipt/receipt.js';
import { UniversalTrustReceipt, UniversalTrustReceiptGenerator } from '../receipts/universal_receipt.js';
import { CanonicalTrustCommitmentV3, computeCanonicalCommitmentDigest } from '../protocol/commitment_v3.js';
import { BesuClient } from '../blockchain/besu/client.js';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface GatewayIngestionRequest {
  commitment: TrustCommitment;
}

export interface GatewayIngestionRequestV3 {
  commitment: CanonicalTrustCommitmentV3;
  customerSignatureHex: string;
  agentSignatureHex: string;
}

export interface GatewayIngestionResponse {
  success: boolean;
  commitmentId?: string;
  receipt?: ImmutableTrustReceipt;
  universalReceipt?: UniversalTrustReceipt;
  proof?: PortableTrustProof;
  error?: string;
}

export interface GatewayStatusResponse {
  gatewayId: string;
  isOnline: boolean;
  besuHealthy?: boolean;
  ledgerHeadSeq: string;
}

/**
 * Customer-facing HTTP/2 server that exposes the Trust Gateway as a network router.
 * In the hardened architecture, the Gateway routes dual-signed commitments directly
 * to the authoritative Hyperledger Besu QBFT network and returns Universal Trust Receipts.
 */
export class GrpcGatewayServer {
  private server: http2.Http2Server | http2.Http2SecureServer;
  private readonly gateway?: TrustGatewayServer;
  private readonly besuClient?: BesuClient;

  constructor(
    gatewayOrClient: TrustGatewayServer | BesuClient,
    tlsConfig?: TlsConfig
  ) {
    if (gatewayOrClient instanceof BesuClient) {
      this.besuClient = gatewayOrClient;
    } else {
      this.gateway = gatewayOrClient;
    }

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

      if (path === '/ingest-v3' && method === 'POST') {
        this.handleIngestV3(stream);
      } else if (path === '/ingest' && method === 'POST') {
        this.handleIngestLegacy(stream);
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

  private handleIngestV3(stream: http2.ServerHttp2Stream): void {
    let data = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      data += chunk;
    });
    stream.on('end', async () => {
      try {
        const req = JSON.parse(data, reviver) as GatewayIngestionRequestV3;

        if (!req.commitment || !this.besuClient) {
          stream.respond({
            [http2.constants.HTTP2_HEADER_STATUS]: 400,
            [http2.constants.HTTP2_HEADER_CONTENT_TYPE]: 'application/json',
          });
          stream.end(JSON.stringify({ success: false, error: 'Missing commitment or BesuClient unconfigured' }, replacer));
          return;
        }

        const digestHex = computeCanonicalCommitmentDigest(req.commitment);

        // Submit directly to authoritative Besu QBFT
        const besuRes = await this.besuClient.submitCommitment({
          tenantId: req.commitment.tenantId,
          databaseId: req.commitment.databaseId,
          checkpointIdHex: req.commitment.checkpointId.replace(/-/g, ''),
          commitSeq: req.commitment.commitSeq,
          epoch: req.commitment.epoch,
          checkpointDigestHex: req.commitment.checkpointDigestHex,
          stateMerkleRootHex: req.commitment.stateMerkleRootHex,
          changeChainHeadHex: req.commitment.changeChainHeadHex,
          previousCommitmentDigestHex: req.commitment.previousCommitmentDigestHex,
          commitmentDigestHex: `0x${digestHex}`,
          logicalTimestampUs: req.commitment.logicalTimestampUs,
          protocolVersion: req.commitment.protocolVersion,
          agentSignatureHex: req.agentSignatureHex,
          customerSignatureHex: req.customerSignatureHex,
        });

        // Produce authoritative Universal Trust Receipt
        const universalReceipt = UniversalTrustReceiptGenerator.createReceipt({
          tenantId: req.commitment.tenantId,
          databaseId: req.commitment.databaseId,
          evidencePlane: {
            checkpointId: req.commitment.checkpointId,
            commitSeq: req.commitment.commitSeq.toString(),
            lsn: req.commitment.lsn,
            checkpointDigestHex: req.commitment.checkpointDigestHex,
            stateMerkleRootHex: req.commitment.stateMerkleRootHex,
            changeChainHeadHex: req.commitment.changeChainHeadHex,
            agentAttestationHex: req.agentSignatureHex,
            customerAuthorizationHex: req.customerSignatureHex,
          },
          trustPlane: {
            networkId: req.commitment.networkId,
            chainId: req.commitment.chainId,
            blockchainTransactionHash: besuRes.txHash,
            blockNumber: besuRes.blockNumber.toString(),
            blockHash: besuRes.blockHash,
            finalityStatus: 'FINALIZED',
            contractAddress: besuRes.contractAddress,
            previousCommitmentDigestHex: req.commitment.previousCommitmentDigestHex,
          },
        });

        const response: GatewayIngestionResponse = {
          success: true,
          commitmentId: req.commitment.checkpointId,
          universalReceipt,
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
        stream.end(JSON.stringify({ success: false, error: err.message ?? 'Internal gateway error' }, replacer));
      }
    });
  }

  private handleIngestLegacy(stream: http2.ServerHttp2Stream): void {
    let data = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      data += chunk;
    });
    stream.on('end', async () => {
      try {
        const req = JSON.parse(data, reviver) as GatewayIngestionRequest;

        if (!req.commitment || !req.commitment.commitmentId || !this.gateway) {
          stream.respond({
            [http2.constants.HTTP2_HEADER_STATUS]: 400,
            [http2.constants.HTTP2_HEADER_CONTENT_TYPE]: 'application/json',
          });
          stream.end(JSON.stringify({ success: false, error: 'Missing or malformed commitment' }, replacer));
          return;
        }

        const result = await this.gateway.ingestCommitment(req.commitment);
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
        stream.end(JSON.stringify({ success: false, error: err.message ?? 'Internal gateway error' }, replacer));
      }
    });
  }

  private async handleStatus(stream: http2.ServerHttp2Stream): Promise<void> {
    let besuHealthy = false;
    if (this.besuClient) {
      besuHealthy = await this.besuClient.isHealthy();
    }

    const gatewayId = this.gateway ? this.gateway.gatewayId : 'wolverine-gateway-router';
    const ledgerHeadSeq = this.gateway ? this.gateway.getLedger().getCurrentSequence().toString() : '0';

    const response: GatewayStatusResponse = {
      gatewayId,
      isOnline: true,
      besuHealthy,
      ledgerHeadSeq,
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
}
