import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  DirectMemoryNetworkTransport,
  StandaloneValidatorProcess,
  StandaloneGatewayProcess,
  StandaloneReplicaProcess,
  StandaloneAgentProcess,
  ImmutableTrustReceiptGenerator,
  ImmutableTrustReceiptVerifier,
} from '../../src/index.js';

describe('Standalone Daemon Process Lifecycle (WDB-0115)', () => {
  it('launches independent validator, gateway, replica, and agent processes and commits checkpoint', async () => {
    const transport = new DirectMemoryNetworkTransport();

    // 1. Launch 5 Standalone Validator Processes
    const validatorProcesses: StandaloneValidatorProcess[] = [];
    const validatorEndpoints = [];
    for (let i = 1; i <= 5; i++) {
      const vProc = new StandaloneValidatorProcess({
        id: `val-node-0${i}`,
        listenHost: '127.0.0.1',
        listenPort: 9300 + i,
        dataDir: `./data/val-node-0${i}`,
        epoch: 1,
      });
      vProc.bind(transport);
      validatorProcesses.push(vProc);
      validatorEndpoints.push({ validatorId: vProc.options.id, endpoint: vProc.endpoint });
    }

    // 2. Launch 3 Standalone Replica Processes
    const replicaProcesses: StandaloneReplicaProcess[] = [];
    const replicaEndpoints = [];
    for (let i = 1; i <= 3; i++) {
      const rProc = new StandaloneReplicaProcess(
        {
          id: `rep-node-0${i}`,
          listenHost: '127.0.0.1',
          listenPort: 9400 + i,
          dataDir: `./data/rep-node-0${i}`,
          role: i === 1 ? 'PRIMARY' : 'BACKUP',
        },
        transport
      );
      replicaProcesses.push(rProc);
      replicaEndpoints.push({ replicaId: `rep-node-0${i}`, endpoint: `http://127.0.0.1:${9400 + i}` });
    }

    // 3. Launch Standalone Gateway Process
    const gatewayProcess = new StandaloneGatewayProcess(
      {
        id: 'gateway-prod-main',
        listenHost: '127.0.0.1',
        listenPort: 8080,
        validatorEndpoints,
        replicaEndpoints,
        requiredQuorum: 4,
      },
      transport
    );

    for (const v of validatorProcesses) {
      gatewayProcess.gateway.registerValidatorKey(v.options.id, v.validator.publicKey);
    }

    // 4. Launch Customer Agent Process
    const agentProcess = new StandaloneAgentProcess({
      tenantId: 'enterprise-daemon-corp',
      databaseId: 'prod-db',
      gateway: gatewayProcess.gateway,
    });

    gatewayProcess.gateway.registerTenant(
      'enterprise-daemon-corp',
      agentProcess.customerPubkey,
      'prod-db'
    );

    // 5. Commit Checkpoint via Agent Process
    const cp = {
      checkpointId: '00000000-0000-0000-0000-000000005001',
      commitSeq: 5001n,
      scope: 'public.orders',
      previousCheckpointId: null,
      merkleRoot: Buffer.alloc(32, 0x77),
      changeChainHead: Buffer.alloc(32, 0x11),
      createdAtUs: 1723500000000000n,
      protocolVersion: 3,
    };

    const commitRes = await agentProcess.client.commitCheckpoint(cp, Buffer.alloc(32, 0xaa));
    expect(commitRes.isSynchronized).toBe(true);
    expect(commitRes.proof).toBeDefined();

    const proof = commitRes.proof!;
    expect(proof.quorumCertificate.quorumCount).toBe(5);

    // 6. Generate and verify Immutable Trust Receipt
    const receipt = ImmutableTrustReceiptGenerator.generateReceipt(
      proof,
      gatewayProcess.gateway.getLedger().getRecords()[0]!.recordDigest
    );
    const verification = ImmutableTrustReceiptVerifier.verifyReceiptOffline(receipt);
    expect(verification.isValid).toBe(true);
  });
});
