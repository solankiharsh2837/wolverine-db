import https from 'node:https';
import http from 'node:http';
import { URL } from 'node:url';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface MtlsServerConfig {
  port: number;
  host?: string;
  certPem: string;
  privPem: string;
  caPem: string;
  requestHandler: (req: http.IncomingMessage, res: http.ServerResponse) => void;
}

export interface MtlsClientConfig {
  certPem?: string;
  privPem?: string;
  caPem?: string;
  rejectUnauthorized?: boolean;
}

export class MtlsServer {
  private server: https.Server;
  private port: number;
  private host: string;
  private listeningPort: number = 0;

  constructor(config: MtlsServerConfig) {
    this.port = config.port;
    this.host = config.host || '127.0.0.1';

    this.server = https.createServer(
      {
        cert: config.certPem,
        key: config.privPem,
        ca: config.caPem,
        requestCert: true,
        rejectUnauthorized: true,
      },
      config.requestHandler
    );
  }

  public async start(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server.listen(this.port, this.host, () => {
        const addr = this.server.address();
        if (typeof addr === 'object' && addr !== null) {
          this.listeningPort = addr.port;
          resolve(addr.port);
        } else {
          resolve(this.port);
        }
      });
      this.server.on('error', reject);
    });
  }

  public get boundPort(): number {
    return this.listeningPort || this.port;
  }

  public async stop(): Promise<void> {
    return new Promise((resolve) => {
      this.server.close(() => resolve());
    });
  }
}

export class MtlsClient {
  private config: MtlsClientConfig;

  constructor(config: MtlsClientConfig) {
    this.config = config;
  }

  public async request<T = any>(
    targetUrl: string,
    method: 'GET' | 'POST' = 'GET',
    payload?: any,
    timeoutMs: number = 5000
  ): Promise<{ statusCode: number; data: T }> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(targetUrl);
      const isHttps = parsed.protocol === 'https:';

      const postData = payload !== undefined ? (typeof payload === 'string' ? payload : JSON.stringify(payload)) : undefined;

      const reqOptions: https.RequestOptions = {
        hostname: parsed.hostname,
        port: parsed.port ? Number(parsed.port) : isHttps ? 443 : 80,
        path: parsed.pathname + parsed.search,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(postData ? { 'Content-Length': Buffer.byteLength(postData) } : {}),
        },
        timeout: timeoutMs,
        ...(isHttps
          ? {
              cert: this.config.certPem,
              key: this.config.privPem,
              ca: this.config.caPem,
              rejectUnauthorized: this.config.rejectUnauthorized ?? true,
            }
          : {}),
      };

      const protocolModule = isHttps ? https : http;
      const req = protocolModule.request(reqOptions, (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          let parsedData: any = body;
          try {
            if (body && (res.headers['content-type']?.includes('json') || body.startsWith('{') || body.startsWith('['))) {
              parsedData = JSON.parse(body);
            }
          } catch {
            // Keep raw body
          }
          resolve({
            statusCode: res.statusCode || 500,
            data: parsedData as T,
          });
        });
      });

      req.on('timeout', () => {
        req.destroy(new WolverineError(WolverineErrorCode.DATABASE_CONNECTION_ERROR, `mTLS request to ${targetUrl} timed out`));
      });

      req.on('error', (err) => {
        reject(err);
      });

      if (postData) {
        req.write(postData);
      }
      req.end();
    });
  }
}
