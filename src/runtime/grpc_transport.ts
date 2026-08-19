import * as http2 from 'node:http2';
import { Buffer } from 'node:buffer';
import { WolverineError, WolverineErrorCode } from '../errors/index.js';
import {
  AttestRpcRequest,
  AttestRpcResponse,
  ReplicateRecordRpcRequest,
  ReplicateRecordRpcResponse,
} from './types.js';
import { INetworkTransport } from './network_transport.js';

export interface TlsConfig {
  cert: Buffer | string;
  key: Buffer | string;
  ca?: Buffer | string;
}

export function replacer(key: string, value: any) {
  if (typeof value === 'bigint') {
    return { __type: 'bigint', value: value.toString() };
  }
  if (value && typeof value === 'object' && value.type === 'Buffer' && Array.isArray(value.data)) {
    return { __type: 'Buffer', value: Buffer.from(value.data).toString('hex') };
  }
  if (Buffer.isBuffer(value)) {
    return { __type: 'Buffer', value: value.toString('hex') };
  }
  return value;
}

export function reviver(key: string, value: any) {
  if (value && typeof value === 'object' && value.__type === 'bigint') {
    return BigInt(value.value);
  }
  if (value && typeof value === 'object' && value.__type === 'Buffer') {
    return Buffer.from(value.value, 'hex');
  }
  return value;
}

export class GrpcNetworkTransport implements INetworkTransport {
  private sessions = new Map<string, http2.ClientHttp2Session>();
  private readonly timeoutMs: number;
  private readonly tlsConfig?: TlsConfig;

  constructor(timeoutMs = 5000, tlsConfig?: TlsConfig) {
    this.timeoutMs = timeoutMs;
    this.tlsConfig = tlsConfig;
  }

  private getSession(endpoint: string): Promise<http2.ClientHttp2Session> {
    return new Promise((resolve, reject) => {
      let session = this.sessions.get(endpoint);
      if (session && !session.closed && !session.destroyed) {
        return resolve(session);
      }

      const isHttps = endpoint.startsWith('https://');
      const options: http2.ClientSessionOptions | http2.SecureClientSessionOptions = isHttps && this.tlsConfig ? {
        cert: this.tlsConfig.cert,
        key: this.tlsConfig.key,
        ca: this.tlsConfig.ca,
        rejectUnauthorized: true
      } : {};

      session = http2.connect(endpoint, options);
      
      let resolved = false;
      
      session.on('error', (err) => {
        this.sessions.delete(endpoint);
        if (!resolved) {
          resolved = true;
          reject(new WolverineError(WolverineErrorCode.NETWORK_ERROR, `Connection error to ${endpoint}: ${err.message}`));
        }
      });
      session.on('close', () => {
        this.sessions.delete(endpoint);
        if (!resolved) {
          resolved = true;
          reject(new WolverineError(WolverineErrorCode.NETWORK_ERROR, `Connection closed before established to ${endpoint}`));
        }
      });
      session.on('connect', () => {
        if (!resolved) {
          resolved = true;
          this.sessions.set(endpoint, session!);
          resolve(session!);
        }
      });
    });
  }

  private async sendRpc<TReq, TRes>(endpoint: string, path: string, request: TReq): Promise<TRes> {
    const session = await this.getSession(endpoint);
    return new Promise((resolve, reject) => {
      let timeoutId: NodeJS.Timeout;
      
      const req = session.request({
        [http2.constants.HTTP2_HEADER_METHOD]: http2.constants.HTTP2_METHOD_POST,
        [http2.constants.HTTP2_HEADER_PATH]: path,
        [http2.constants.HTTP2_HEADER_CONTENT_TYPE]: 'application/json',
      });

      req.on('error', (err) => {
        clearTimeout(timeoutId);
        reject(new WolverineError(WolverineErrorCode.NETWORK_ERROR, `RPC error to ${endpoint}${path}: ${err.message}`));
      });

      req.on('response', (headers) => {
        const status = headers[http2.constants.HTTP2_HEADER_STATUS];
        if (Number(status) !== 200) {
          clearTimeout(timeoutId);
          reject(new WolverineError(WolverineErrorCode.NETWORK_ERROR, `RPC returned non-200 status: ${status}`));
        }
      });

      req.setEncoding('utf8');
      let data = '';
      req.on('data', (chunk) => {
        data += chunk;
      });

      req.on('end', () => {
        clearTimeout(timeoutId);
        try {
          const res = JSON.parse(data, reviver) as TRes;
          resolve(res);
        } catch (err: any) {
          reject(new WolverineError(WolverineErrorCode.NETWORK_ERROR, `Failed to parse RPC response: ${err.message}`));
        }
      });

      const payload = JSON.stringify(request, replacer);
      req.write(payload);
      req.end();

      timeoutId = setTimeout(() => {
        req.close(http2.constants.NGHTTP2_CANCEL);
        reject(new WolverineError(WolverineErrorCode.NETWORK_TIMEOUT, `RPC timeout to ${endpoint}${path} after ${this.timeoutMs}ms`));
      }, this.timeoutMs);
    });
  }

  public async sendAttestRpc(endpoint: string, request: AttestRpcRequest): Promise<AttestRpcResponse> {
    return this.sendRpc<AttestRpcRequest, AttestRpcResponse>(endpoint, '/attest', request);
  }

  public async sendReplicateRpc(endpoint: string, request: ReplicateRecordRpcRequest): Promise<ReplicateRecordRpcResponse> {
    return this.sendRpc<ReplicateRecordRpcRequest, ReplicateRecordRpcResponse>(endpoint, '/replicate', request);
  }

  public closeAll(): void {
    for (const session of this.sessions.values()) {
      if (!session.closed) {
        session.close();
      }
    }
    this.sessions.clear();
  }
}

export class GrpcAttestServer {
  private server: http2.Http2Server | http2.Http2SecureServer;

  constructor(
    private readonly handler: (req: AttestRpcRequest) => Promise<AttestRpcResponse>,
    private readonly tlsConfig?: TlsConfig
  ) {
    if (this.tlsConfig) {
      this.server = http2.createSecureServer({
        cert: this.tlsConfig.cert,
        key: this.tlsConfig.key,
        ca: this.tlsConfig.ca,
      });
    } else {
      this.server = http2.createServer();
    }

    this.server.on('stream', (stream, headers) => {
      const path = headers[http2.constants.HTTP2_HEADER_PATH];
      const method = headers[http2.constants.HTTP2_HEADER_METHOD];

      if (path === '/attest' && method === 'POST') {
        let data = '';
        stream.setEncoding('utf8');
        stream.on('data', (chunk) => {
          data += chunk;
        });
        stream.on('end', async () => {
          try {
            const req = JSON.parse(data, reviver) as AttestRpcRequest;
            const res = await this.handler(req);
            stream.respond({
              [http2.constants.HTTP2_HEADER_STATUS]: 200,
              [http2.constants.HTTP2_HEADER_CONTENT_TYPE]: 'application/json',
            });
            stream.end(JSON.stringify(res, replacer));
          } catch (err: any) {
            stream.respond({
              [http2.constants.HTTP2_HEADER_STATUS]: 500,
            });
            stream.end(JSON.stringify({ error: err.message }));
          }
        });
      } else {
        stream.respond({
          [http2.constants.HTTP2_HEADER_STATUS]: 404,
        });
        stream.end();
      }
    });
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

export class GrpcReplicateServer {
  private server: http2.Http2Server | http2.Http2SecureServer;

  constructor(
    private readonly handler: (req: ReplicateRecordRpcRequest) => Promise<ReplicateRecordRpcResponse>,
    private readonly tlsConfig?: TlsConfig
  ) {
    if (this.tlsConfig) {
      this.server = http2.createSecureServer({
        cert: this.tlsConfig.cert,
        key: this.tlsConfig.key,
        ca: this.tlsConfig.ca,
      });
    } else {
      this.server = http2.createServer();
    }

    this.server.on('stream', (stream, headers) => {
      const path = headers[http2.constants.HTTP2_HEADER_PATH];
      const method = headers[http2.constants.HTTP2_HEADER_METHOD];

      if (path === '/replicate' && method === 'POST') {
        let data = '';
        stream.setEncoding('utf8');
        stream.on('data', (chunk) => {
          data += chunk;
        });
        stream.on('end', async () => {
          try {
            const req = JSON.parse(data, reviver) as ReplicateRecordRpcRequest;
            const res = await this.handler(req);
            stream.respond({
              [http2.constants.HTTP2_HEADER_STATUS]: 200,
              [http2.constants.HTTP2_HEADER_CONTENT_TYPE]: 'application/json',
            });
            stream.end(JSON.stringify(res, replacer));
          } catch (err: any) {
            stream.respond({
              [http2.constants.HTTP2_HEADER_STATUS]: 500,
            });
            stream.end(JSON.stringify({ error: err.message }));
          }
        });
      } else {
        stream.respond({
          [http2.constants.HTTP2_HEADER_STATUS]: 404,
        });
        stream.end();
      }
    });
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
