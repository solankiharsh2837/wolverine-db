import { describe, it, expect, vi } from 'vitest';
import crypto from 'node:crypto';
import {
  TrustGatewayServer,
} from '../../src/runtime/gateway.js';
import {
  TrustGatewayConfig,
  INetworkTransport,
  AttestRpcResponse,
  ReplicateRpcResponse,
  PeerSyncRpcResponse,
} from '../../src/runtime/types.js';
import { WolverineTrustLedger } from '../../src/trust_network/ledger.js';
import { TrustValidator } from '../../src/trust_network/validator.js';
import { TrustCommitment } from '../../src/trust_network/types.js';
import { createSignedCustomerCommitment } from '../../src/trust_network/commitment.js';
import { WolverineTrustNetworkService } from '../../src/trust_network/service.js';
import { WolverineErrorCode } from '../../src/errors/codes.js';

class MockTrackingTransport implements INetworkTransport {
  public rpcCallCount: number = 0;
  private validators: Map<string, TrustValidator> = new Map();

  public registerValidator(validator: TrustValidator): void {
    this.validators.set(validator.validatorId, validator);
  }

  public async sendAttestRpc(
    endpoint: string,
    params: { commitment: TrustCommitment; tenantPubkeyHex: string }
  ): Promise<AttestRpcResponse> {
    this.rpcCallCount++;
    const v = Array.from(this.validators.values()).find(
      (val) => val.validatorId === endpoint || endpoint.includes(val.validatorId)
    );
    if (!v) {
      return { success: false, error: `Validator ${endpoint} not found` };
    }
    const tenantKey = Buffer.from(params.tenantPubkeyHex, 'hex');
    const attestation = v.attestCommitment(params.commitment, tenantKey);
    return { success: true, attestation };
  }

  public async sendReplicateRpc(_endpoint: string, _params: any): Promise<ReplicateRpcResponse> {
    return { success: true, replicatedSeq: '1' };
  }

  public async sendPeerSyncRpc(_endpoint: string, _params: any): Promise<PeerSyncRpcResponse> {
    return { success: true, records: [] };
  }
}

function generateKeyPair() {
  const pair = crypto.generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  return { publicKey, privateKey: pair.privateKey };
}

describe('Gateway Boundary Signer Authentication (Issue #3)', () => {
  const totalValidators = 5;
  const requiredQuorum = 3;

  function setupGateway() {
    const transport = new MockTrackingTransport();
    const ledger = new WolverineTrustLedger();

    const validatorEndpoints = [];
    const validators: TrustValidator[] = [];

    for (let i = 1; i <= totalValidators; i++) {
      const vId = `val-${i}`;
      const validator = new TrustValidator(vId);
      validators.push(validator);
      transport.registerValidator(validator);
      validatorEndpoints.push({ validatorId: vId, endpoint: `mock://${vId}` });
    }

    const config: TrustGatewayConfig = {
      gatewayId: 'gateway-auth-01',
      validatorEndpoints,
      replicaEndpoints: [],
      requiredQuorum,
      totalValidators,
    };

    const server = new TrustGatewayServer(config, transport, ledger);

    for (const val of validators) {
      server.registerValidatorKey(val.validatorId, val.publicKey);
    }

    return { server, transport, ledger, validators };
  }

  it('accepts legitimate signed commitment from registered tenant', async () => {
    const { server, transport } = setupGateway();
    const tenantKey = generateKeyPair();
    const tenantId = 'tenant-auth-valid';
    const databaseId = 'db-valid';

    server.registerTenant(tenantId, tenantKey.publicKey, databaseId);

    const commitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId,
        databaseId,
        checkpointId: crypto.randomUUID(),
        commitSeq: 1n,
        checkpointDigest: crypto.randomBytes(32),
        previousTrustCommitment: crypto.randomBytes(32),
        epoch: 1,
        validatorSetId: 'valset-v1',
      },
      tenantKey.privateKey,
      tenantKey.publicKey
    );

    const result = await server.ingestCommitment(commitment);
    expect(result.certificate).toBeDefined();
    expect(result.proof).toBeDefined();
    expect(transport.rpcCallCount).toBe(totalValidators);
  });

  it('rejects forged commitment signature at gateway ingress WITHOUT dispatching to validators', async () => {
    const { server, transport } = setupGateway();
    const tenantKey = generateKeyPair();
    const tenantId = 'tenant-auth-forge';
    const databaseId = 'db-forge';

    server.registerTenant(tenantId, tenantKey.publicKey, databaseId);

    const commitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId,
        databaseId,
        checkpointId: crypto.randomUUID(),
        commitSeq: 1n,
        checkpointDigest: crypto.randomBytes(32),
        previousTrustCommitment: crypto.randomBytes(32),
        epoch: 1,
        validatorSetId: 'valset-v1',
      },
      tenantKey.privateKey,
      tenantKey.publicKey
    );

    // Adversary forges / corrupts signature
    commitment.customerSignature = crypto.randomBytes(64);

    await expect(server.ingestCommitment(commitment)).rejects.toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.UNAUTHORIZED_MUTATION })
    );

    // Assert defense-in-depth: No RPCs were dispatched to downstream validators
    expect(transport.rpcCallCount).toBe(0);
  });

  it('rejects commitment signed with key mismatch against registered tenant key', async () => {
    const { server, transport } = setupGateway();
    const registeredTenantKey = generateKeyPair();
    const rogueKey = generateKeyPair();

    const tenantId = 'tenant-auth-mismatch';
    const databaseId = 'db-mismatch';

    server.registerTenant(tenantId, registeredTenantKey.publicKey, databaseId);

    // Attacker signs commitment using rogue key instead of registered tenant key
    const commitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId,
        databaseId,
        checkpointId: crypto.randomUUID(),
        commitSeq: 1n,
        checkpointDigest: crypto.randomBytes(32),
        previousTrustCommitment: crypto.randomBytes(32),
        epoch: 1,
        validatorSetId: 'valset-v1',
      },
      rogueKey.privateKey,
      rogueKey.publicKey
    );

    await expect(server.ingestCommitment(commitment)).rejects.toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.UNAUTHORIZED_MUTATION })
    );

    expect(transport.rpcCallCount).toBe(0);
  });

  it('rejects commitment with tampered commitmentDigest at gateway boundary', async () => {
    const { server, transport } = setupGateway();
    const tenantKey = generateKeyPair();
    const tenantId = 'tenant-auth-tamper';
    const databaseId = 'db-tamper';

    server.registerTenant(tenantId, tenantKey.publicKey, databaseId);

    const commitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId,
        databaseId,
        checkpointId: crypto.randomUUID(),
        commitSeq: 1n,
        checkpointDigest: crypto.randomBytes(32),
        previousTrustCommitment: crypto.randomBytes(32),
        epoch: 1,
        validatorSetId: 'valset-v1',
      },
      tenantKey.privateKey,
      tenantKey.publicKey
    );

    // Tamper digest
    commitment.commitmentDigest = crypto.randomBytes(32);

    await expect(server.ingestCommitment(commitment)).rejects.toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.UNAUTHORIZED_MUTATION })
    );

    expect(transport.rpcCallCount).toBe(0);
  });

  it('verifies signature authentication in TrustNetworkService as well', async () => {
    const service = new WolverineTrustNetworkService(3, 5);
    const tenantKey = generateKeyPair();
    const tenantId = 'service-auth-tenant';
    const databaseId = 'service-db';

    service.registerTenant(tenantId, tenantKey.publicKey, databaseId);

    const validCommitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId,
        databaseId,
        checkpointId: crypto.randomUUID(),
        commitSeq: 1n,
        checkpointDigest: crypto.randomBytes(32),
        previousTrustCommitment: crypto.randomBytes(32),
        epoch: 1,
        validatorSetId: 'valset-genesis',
      },
      tenantKey.privateKey,
      tenantKey.publicKey
    );

    const validResult = await service.submitCommitment(validCommitment);
    expect(validResult.certificate).toBeDefined();

    // Forged signature
    const forgedCommitment = createSignedCustomerCommitment(
      {
        commitmentId: crypto.randomUUID(),
        tenantId,
        databaseId,
        checkpointId: crypto.randomUUID(),
        commitSeq: 2n,
        checkpointDigest: crypto.randomBytes(32),
        previousTrustCommitment: validCommitment.commitmentDigest,
        epoch: 1,
        validatorSetId: 'valset-genesis',
      },
      tenantKey.privateKey,
      tenantKey.publicKey
    );
    forgedCommitment.customerSignature = crypto.randomBytes(64);

    await expect(service.submitCommitment(forgedCommitment)).rejects.toThrowError(
      expect.objectContaining({ code: WolverineErrorCode.UNAUTHORIZED_MUTATION })
    );
  });
});
