import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as http2 from 'node:http2';
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import { GrpcGatewayServer, GatewayIngestionRequest, GatewayIngestionResponse } from '../../src/runtime/grpc_gateway_server.js';
import { DistributedTrustCluster } from '../../src/runtime/cluster.js';
import { createSignedCustomerCommitment } from '../../src/trust_network/commitment.js';
import { computeCheckpointDigest } from '../../src/checkpoint/anchor.js';
import { replacer, reviver } from '../../src/runtime/grpc_transport.js';

describe('GrpcGatewayServer E2E', () => {
  let cluster: DistributedTrustCluster;
  let gatewayServer: GrpcGatewayServer;
  let customerKeyPair: { publicKey: Buffer; privateKey: crypto.KeyObject };
  const GATEWAY_PORT = 9876;

  beforeAll(async () => {
    // Generate customer Ed25519 key pair
    const kp = crypto.generateKeyPairSync('ed25519');
    const pubBytes = kp.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    customerKeyPair = { publicKey: pubBytes, privateKey: kp.privateKey };

    // Create in-memory cluster (tests use DirectMemoryTransport for validators)
    cluster = new DistributedTrustCluster({
      requiredQuorum: 3,
      totalValidators: 5,
      totalReplicas: 1,
    });

    // Register the customer tenant
    cluster.gateway.registerTenant('tenant-test', customerKeyPair.publicKey, 'db-test');

    // Create HTTP/2 gateway server wrapping the cluster gateway
    gatewayServer = new GrpcGatewayServer(cluster.gateway);
    await gatewayServer.listen(GATEWAY_PORT, '127.0.0.1');
  });

  afterAll(async () => {
    await gatewayServer.close();
  });

  function sendRequest(path: string, method: string, body?: any): Promise<{ status: number; data: any }> {
    return new Promise((resolve, reject) => {
      const session = http2.connect(`http://127.0.0.1:${GATEWAY_PORT}`);
      session.on('error', reject);

      const headers: Record<string, string> = {
        [http2.constants.HTTP2_HEADER_METHOD]: method,
        [http2.constants.HTTP2_HEADER_PATH]: path,
      };

      if (body) {
        headers[http2.constants.HTTP2_HEADER_CONTENT_TYPE] = 'application/json';
      }

      const req = session.request(headers);
      if (body) {
        req.write(JSON.stringify(body, replacer));
      }
      req.end();

      req.setEncoding('utf8');
      let data = '';
      let status = 0;

      req.on('response', (h) => {
        status = Number(h[http2.constants.HTTP2_HEADER_STATUS]);
      });
      req.on('data', (chunk) => { data += chunk; });
      req.on('end', () => {
        session.close();
        try {
          resolve({ status, data: JSON.parse(data, reviver) });
        } catch {
          resolve({ status, data });
        }
      });
    });
  }

  it('should respond to /health with healthy status', async () => {
    const res = await sendRequest('/health', 'GET');
    expect(res.status).toBe(200);
    expect(res.data.status).toBe('healthy');
  });

  it('should respond to /status with gateway info', async () => {
    const res = await sendRequest('/status', 'GET');
    expect(res.status).toBe(200);
    expect(res.data.gatewayId).toBe('gateway-prod-01');
    expect(res.data.isOnline).toBe(true);
  });

  it('should return 404 for unknown paths', async () => {
    const res = await sendRequest('/unknown', 'GET');
    expect(res.status).toBe(404);
  });

  it('should reject malformed commitment on /ingest', async () => {
    const res = await sendRequest('/ingest', 'POST', { commitment: {} });
    expect(res.status).toBe(400);
    expect(res.data.success).toBe(false);
  });

  it('should ingest a valid commitment and return a trust receipt', async () => {
    const checkpointId = crypto.randomUUID();
    const commitSeq = 1n;
    const scope = 'public.transactions';
    const merkleRoot = crypto.randomBytes(32);
    const changeChainHead = crypto.randomBytes(32);
    const createdAtUs = BigInt(Date.now()) * 1000n;

    const checkpointDigest = computeCheckpointDigest({
      checkpointId,
      commitSeq,
      scope,
      merkleRoot,
      changeChainHead,
      createdAtUs,
      protocolVersion: 1,
      previousCheckpointId: null,
    });

    const commitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'tenant-test',
        databaseId: 'db-test',
        checkpointId,
        commitSeq,
        checkpointDigest,
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      customerKeyPair.privateKey,
      customerKeyPair.publicKey
    );

    const body: GatewayIngestionRequest = { commitment };
    const res = await sendRequest('/ingest', 'POST', body);

    expect(res.status).toBe(200);
    expect(res.data.success).toBe(true);
    expect(res.data.commitmentId).toBe(commitment.commitmentId);
    expect(res.data.receipt).toBeDefined();
    expect(res.data.receipt.receiptId).toContain('rcpt-');
    expect(res.data.proof).toBeDefined();
    expect(res.data.proof.proofVersion).toBe(1);
    expect(res.data.proof.tenantId).toBe('tenant-test');
    expect(res.data.proof.databaseId).toBe('db-test');
  });

  it('should reject commitment from unregistered tenant', async () => {
    const checkpointDigest = crypto.randomBytes(32);
    const commitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId: 'tenant-unknown',
        databaseId: 'db-test',
        checkpointId: crypto.randomUUID(),
        commitSeq: 1n,
        checkpointDigest,
        previousTrustCommitment: Buffer.alloc(32, 0),
      },
      customerKeyPair.privateKey,
      customerKeyPair.publicKey
    );

    const res = await sendRequest('/ingest', 'POST', { commitment });
    expect(res.status).toBe(422);
    expect(res.data.success).toBe(false);
    expect(res.data.error).toContain('Unregistered tenant');
  });
});
