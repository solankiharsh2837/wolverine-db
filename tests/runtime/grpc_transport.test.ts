import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Buffer } from 'node:buffer';
import { GrpcNetworkTransport, GrpcAttestServer, GrpcReplicateServer, replacer, reviver } from '../../src/runtime/grpc_transport.js';
import { AttestRpcRequest, AttestRpcResponse, ReplicateRecordRpcRequest, ReplicateRecordRpcResponse } from '../../src/runtime/types.js';

describe('GrpcNetworkTransport', () => {
  let transport: GrpcNetworkTransport;
  let attestServer: GrpcAttestServer;
  let replicateServer: GrpcReplicateServer;

  beforeAll(async () => {
    transport = new GrpcNetworkTransport(1000); // 1s timeout

    attestServer = new GrpcAttestServer(async (req) => {
      if (req.tenantPubkeyHex === 'error') {
        throw new Error('Test error');
      }
      if (req.tenantPubkeyHex === 'timeout') {
        await new Promise((resolve) => setTimeout(resolve, 1500));
      }
      return {
        success: true,
        attestation: {
          validatorId: 'val-1',
          signatureHex: 'sig123',
        }
      };
    });
    await attestServer.listen(9876, '127.0.0.1');

    replicateServer = new GrpcReplicateServer(async (req) => {
      return {
        success: true,
        acknowledgedSeq: '42'
      };
    });
    await replicateServer.listen(9877, '127.0.0.1');
  });

  afterAll(async () => {
    transport.closeAll();
    await attestServer.close();
    await replicateServer.close();
  });

  it('should successfully send and receive attest RPC', async () => {
    const req: AttestRpcRequest = {
      tenantPubkeyHex: 'abcdef',
      commitment: {
        epoch: 1,
        ledgerSeq: 10n,
        checkpointId: 'cp1',
        checkpointDigestHex: 'digest1',
      }
    };
    const res = await transport.sendAttestRpc('http://127.0.0.1:9876', req);
    expect(res.success).toBe(true);
    expect(res.attestation?.validatorId).toBe('val-1');
  });

  it('should handle bigint and Buffer serialization in replacer/reviver directly', () => {
    const obj = {
      val: 42n,
      buf: Buffer.from('hello'),
    };
    const str = JSON.stringify(obj, replacer);
    const parsed = JSON.parse(str, reviver);
    expect(parsed.val).toBe(42n);
    expect(Buffer.isBuffer(parsed.buf)).toBe(true);
    expect(parsed.buf.toString('utf8')).toBe('hello');
  });

  it('should successfully send and receive replicate RPC', async () => {
    const req: ReplicateRecordRpcRequest = {
      record: {
        recordId: 'rec1',
        recordType: 'LOG',
        payload: Buffer.from('payload'),
        epoch: 1,
        ledgerSeq: 42n,
        timestampUs: 100n,
        validatorSetId: 'valset',
        tenantId: 'tenant1',
        databaseId: 'db1',
      }
    };
    const res = await transport.sendReplicateRpc('http://127.0.0.1:9877', req);
    expect(res.success).toBe(true);
    expect(res.acknowledgedSeq).toBe('42');
  });

  it('should handle RPC timeout', async () => {
    const req: AttestRpcRequest = {
      tenantPubkeyHex: 'timeout',
      commitment: {
        epoch: 1,
        ledgerSeq: 10n,
        checkpointId: 'cp1',
        checkpointDigestHex: 'digest1',
      }
    };
    await expect(transport.sendAttestRpc('http://127.0.0.1:9876', req)).rejects.toThrow(/RPC timeout/);
  });

  it('should handle unreachable endpoint', async () => {
    const req: AttestRpcRequest = {
      tenantPubkeyHex: 'abcdef',
      commitment: {
        epoch: 1,
        ledgerSeq: 10n,
        checkpointId: 'cp1',
        checkpointDigestHex: 'digest1',
      }
    };
    await expect(transport.sendAttestRpc('http://127.0.0.1:9999', req)).rejects.toThrow(/Connection error|Connection closed/);
  });

  it('should handle server errors gracefully', async () => {
    const req: AttestRpcRequest = {
      tenantPubkeyHex: 'error',
      commitment: {
        epoch: 1,
        ledgerSeq: 10n,
        checkpointId: 'cp1',
        checkpointDigestHex: 'digest1',
      }
    };
    await expect(transport.sendAttestRpc('http://127.0.0.1:9876', req)).rejects.toThrow(/RPC returned non-200 status: 500/);
  });
});
