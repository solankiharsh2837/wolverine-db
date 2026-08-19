import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { generateClusterTlsPki, MtlsServer, MtlsClient } from '../src/index.js';

describe('Milestone 3.2 — Mandatory Mutual TLS (mTLS) Transport & Certificate Boundaries', () => {
  const pki = generateClusterTlsPki();
  let server: MtlsServer;
  let serverPort: number;

  beforeAll(async () => {
    server = new MtlsServer({
      port: 0,
      host: '127.0.0.1',
      certPem: pki.gateway.certPem,
      privPem: pki.gateway.privPem,
      caPem: pki.ca.certPem,
      requestHandler: (req, res) => {
        const clientCert = (req.socket as any).getPeerCertificate();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            status: 'AUTHENTICATED',
            clientCn: clientCert.subject?.CN || 'UNKNOWN',
          })
        );
      },
    });
    serverPort = await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('1. Valid mTLS Handshake: legitimate Agent client with valid CA certificate connects successfully', async () => {
    const client = new MtlsClient({
      certPem: pki.agent.certPem,
      privPem: pki.agent.privPem,
      caPem: pki.ca.certPem,
      rejectUnauthorized: true,
    });

    const res = await client.request(`https://127.0.0.1:${serverPort}/v1/health`, 'GET');

    expect(res.statusCode).toBe(200);
    expect(res.data.status).toBe('AUTHENTICATED');
    expect(res.data.clientCn).toBe('wolverine-agent');
  });

  it('2. Unauthenticated Handshake Rejection: client without certificate is rejected during TLS handshake', async () => {
    const unauthenticatedClient = new MtlsClient({
      // NO CLIENT CERT OR KEY PRESENTED
      caPem: pki.ca.certPem,
      rejectUnauthorized: true,
    });

    await expect(
      unauthenticatedClient.request(`https://127.0.0.1:${serverPort}/v1/health`, 'GET')
    ).rejects.toThrowError();
  });

  it('3. Untrusted CA Certificate Rejection: client signed by rogue CA is rejected during handshake', async () => {
    const rogueClient = new MtlsClient({
      certPem: pki.untrustedClient.certPem,
      privPem: pki.untrustedClient.privPem,
      caPem: pki.ca.certPem,
      rejectUnauthorized: true,
    });

    await expect(
      rogueClient.request(`https://127.0.0.1:${serverPort}/v1/health`, 'GET')
    ).rejects.toThrowError();
  });

  it('4. Plaintext HTTP Connection Rejection: plaintext HTTP request to mTLS port is rejected', async () => {
    const result = await new Promise<{ error?: any; status?: number }>((resolve) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port: serverPort,
          path: '/v1/health',
          method: 'GET',
          timeout: 2000,
        },
        (res) => {
          resolve({ status: res.statusCode });
        }
      );
      req.on('error', (err) => resolve({ error: err }));
      req.on('timeout', () => {
        req.destroy();
        resolve({ error: 'TIMEOUT' });
      });
      req.end();
    });

    // Plaintext HTTP request over TLS port must fail with socket error or hangup
    expect(result.error || result.status !== 200).toBeTruthy();
  });
});
