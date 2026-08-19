import { describe, it, expect } from 'vitest';
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
import { OfflineTrustProofVerifier } from '../../src/trust_network/proof.js';
import { TrustConsensusEngine } from '../../src/trust_network/consensus.js';

class MockDirectTransport implements INetworkTransport {
  private validators: Map<string, TrustValidator> = new Map();
  private tenantKeys: Map<string, Buffer> = new Map();

  public registerValidator(validator: TrustValidator): void {
    this.validators.set(validator.validatorId, validator);
  }

  public registerTenantKey(tenantId: string, pubKey: Buffer): void {
    this.tenantKeys.set(tenantId, pubKey);
  }

  public async sendAttestRpc(
    endpoint: string,
    params: { commitment: TrustCommitment; tenantPubkeyHex: string }
  ): Promise<AttestRpcResponse> {
    const v = Array.from(this.validators.values()).find((val) => val.validatorId === endpoint || endpoint.includes(val.validatorId));
    if (!v) {
      return { success: false, error: `Validator endpoint ${endpoint} not found` };
    }

    try {
      const tenantKey = Buffer.from(params.tenantPubkeyHex, 'hex');
      const attestation = v.attestCommitment(params.commitment, tenantKey);
      return { success: true, attestation };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  }

  public async sendReplicateRpc(_endpoint: string, _params: any): Promise<ReplicateRpcResponse> {
    return { success: true, replicatedSeq: '1' };
  }

  public async sendPeerSyncRpc(_endpoint: string, _params: any): Promise<PeerSyncRpcResponse> {
    return { success: true, records: [] };
  }
}

function createSignedCommitment(
  tenantId: string,
  databaseId: string,
  commitSeq: bigint,
  customerKeyPair: { publicKey: Buffer; privateKey: crypto.KeyObject }
): TrustCommitment {
  const commitmentId = crypto.randomUUID();
  const checkpointId = crypto.randomUUID();
  const checkpointDigest = crypto.randomBytes(32);
  const previousTrustCommitment = crypto.randomBytes(32);

  return createSignedCustomerCommitment(
    {
      commitmentId,
      tenantId,
      databaseId,
      checkpointId,
      commitSeq,
      checkpointDigest,
      previousTrustCommitment,
      epoch: 1,
      validatorSetId: 'valset-v1',
    },
    customerKeyPair.privateKey,
    customerKeyPair.publicKey
  );
}

describe('Trust Gateway Ledger Record Binding (Issue #2)', () => {
  const totalValidators = 5;
  const requiredQuorum = 3;

  function setupGateway() {
    const transport = new MockDirectTransport();
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
      gatewayId: 'gateway-01',
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

  function generateTenantKey() {
    const pair = crypto.generateKeyPairSync('ed25519');
    const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return { publicKey, privateKey: pair.privateKey };
  }

  it('WolverineTrustLedger provides exact commitment and certificate lookups', () => {
    const ledger = new WolverineTrustLedger();
    const commitmentId = 'comm-001';
    const certDigest = Buffer.alloc(32, 0x99);

    ledger.appendRecord('GENESIS', { message: 'genesis record' });

    const rec = ledger.appendRecord(
      'FINALIZATION',
      {
        commitmentId,
        commitSeq: '10',
        commitmentDigestHex: 'aabbcc',
        certificateDigestHex: certDigest.toString('hex'),
      },
      1,
      'valset-01',
      'tenant-a',
      'db-01'
    );

    ledger.appendRecord('GENESIS', { message: 'subsequent record' });

    const byCommId = ledger.getRecordByCommitmentId(commitmentId);
    expect(byCommId).toBeDefined();
    expect(byCommId?.ledgerSeq).toBe(rec.ledgerSeq);
    expect(byCommId?.payload['commitmentId']).toBe(commitmentId);

    const byCert = ledger.getRecordByCertificateDigest(certDigest);
    expect(byCert).toBeDefined();
    expect(byCert?.ledgerSeq).toBe(rec.ledgerSeq);
  });

  it('TrustConsensusEngine.processAttestationsWithRecord returns both certificate and exact appended record', () => {
    const ledger = new WolverineTrustLedger();
    const consensusEngine = new TrustConsensusEngine(ledger, 3, 5);

    const validators = [1, 2, 3, 4, 5].map((i) => new TrustValidator(`val-${i}`));
    for (const v of validators) {
      consensusEngine.registerValidatorKey(v.validatorId, v.publicKey);
    }

    const tenantKey = generateTenantKey();
    const commitment = createSignedCommitment('tenant-1', 'db-1', 1n, tenantKey);
    const attestations = validators.map((v) => v.attestCommitment(commitment, tenantKey.publicKey));

    const { certificate, ledgerRecord } = consensusEngine.processAttestationsWithRecord(commitment, attestations);

    expect(certificate.commitmentId).toBe(commitment.commitmentId);
    expect(ledgerRecord.payload['commitmentId']).toBe(commitment.commitmentId);
    expect(ledgerRecord.payload['commitmentDigestHex']).toBe(commitment.commitmentDigest.toString('hex'));
    expect(ledgerRecord.payload['certificateDigestHex']).toBe(certificate.certificateDigest.toString('hex'));
  });

  it('TrustGatewayServer.ingestCommitment returns ledgerRecord and proof cryptographically bound to the commitment', async () => {
    const { server, ledger } = setupGateway();

    // Pre-populate ledger with unrelated historical records to ensure we do not just read the tail
    ledger.appendRecord('GENESIS', { message: 'unrelated record 1' });
    ledger.appendRecord('GENESIS', { message: 'unrelated record 2' });

    const tenantKey = generateTenantKey();
    const tenantId = 'tenant-prod';
    const databaseId = 'db-main';

    server.registerTenant(tenantId, tenantKey.publicKey, databaseId);

    const commitment = createSignedCommitment(tenantId, databaseId, 100n, tenantKey);

    const result = await server.ingestCommitment(commitment);

    // Verify returned ledger record matches the commitment
    expect(result.ledgerRecord.payload['commitmentId']).toBe(commitment.commitmentId);
    expect(result.ledgerRecord.payload['commitSeq']).toBe('100');
    expect(result.ledgerRecord.payload['commitmentDigestHex']).toBe(commitment.commitmentDigest.toString('hex'));
    expect(result.ledgerRecord.payload['certificateDigestHex']).toBe(result.certificate.certificateDigest.toString('hex'));

    // Verify proof matches
    expect(result.proof.commitment.commitmentId).toBe(commitment.commitmentId);
    expect(result.proof.ledgerRecord.recordDigestHex).toBe(result.ledgerRecord.recordDigest.toString('hex'));

    // Verify offline proof verification passes
    const verifyResult = OfflineTrustProofVerifier.verifyPortableProof(result.proof);
    expect(verifyResult.isValid).toBe(true);
    expect(verifyResult.status).toBe('VALID');
  });

  it('guarantees record binding across concurrent multi-tenant ingestions', async () => {
    const { server } = setupGateway();

    const tenantAKey = generateTenantKey();
    const tenantBKey = generateTenantKey();

    server.registerTenant('tenant-A', tenantAKey.publicKey, 'db-A');
    server.registerTenant('tenant-B', tenantBKey.publicKey, 'db-B');

    const commitmentA = createSignedCommitment('tenant-A', 'db-A', 1n, tenantAKey);
    const commitmentB = createSignedCommitment('tenant-B', 'db-B', 1n, tenantBKey);

    // Ingest concurrently
    const [resultA, resultB] = await Promise.all([
      server.ingestCommitment(commitmentA),
      server.ingestCommitment(commitmentB),
    ]);

    expect(resultA.ledgerRecord.payload['commitmentId']).toBe(commitmentA.commitmentId);
    expect(resultA.proof.commitment.commitmentId).toBe(commitmentA.commitmentId);
    expect(resultA.proof.ledgerRecord.recordDigestHex).toBe(resultA.ledgerRecord.recordDigest.toString('hex'));

    expect(resultB.ledgerRecord.payload['commitmentId']).toBe(commitmentB.commitmentId);
    expect(resultB.proof.commitment.commitmentId).toBe(commitmentB.commitmentId);
    expect(resultB.proof.ledgerRecord.recordDigestHex).toBe(resultB.ledgerRecord.recordDigest.toString('hex'));

    expect(OfflineTrustProofVerifier.verifyPortableProof(resultA.proof).isValid).toBe(true);
    expect(OfflineTrustProofVerifier.verifyPortableProof(resultB.proof).isValid).toBe(true);
  });
});
