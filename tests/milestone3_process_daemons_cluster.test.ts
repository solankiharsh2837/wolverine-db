import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  generateClusterTlsPki,
  ValidatorSetManager,
  WdbValidatorDaemon,
  WdbGatewayDaemon,
  WdbAgentDaemon,
  SoftwareCustomerSigner,
  IndependentQuorumVerifier,
  BootstrapSnapshot,
} from '../src/index.js';

describe('Milestone 3.1 & 3.3 — Process-Separated Multi-Daemon Cluster over mTLS', () => {
  const testDir = path.join(process.cwd(), 'tmp', 'test_m3_cluster');
  const pki = generateClusterTlsPki();

  // 5 Validators
  const valKeypairs = [
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
  ];

  const agentKeypair = crypto.generateKeyPairSync('ed25519');
  const customerKeypair = crypto.generateKeyPairSync('ed25519');

  const agentPubkey = agentKeypair.publicKey.export({ format: 'der', type: 'spki' });
  const customerPubkey = customerKeypair.publicKey.export({ format: 'der', type: 'spki' });

  const valNodes = valKeypairs.map((kp, idx) => ({
    validatorId: `validator-0${idx + 1}`,
    publicKeyHex: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
    weight: 1,
  }));

  const valSetManager = new ValidatorSetManager({
    validatorSetId: 'valset-cluster-m3',
    epoch: 1,
    quorumThreshold: 4,
    totalValidators: 5,
    validators: valNodes,
  });

  let validatorDaemons: WdbValidatorDaemon[] = [];
  let validatorPorts: number[] = [];
  let gatewayDaemon: WdbGatewayDaemon;
  let gatewayPort: number;
  let agentDaemon: WdbAgentDaemon;

  beforeAll(async () => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }

    // 1. Start 5 independent Validator daemons
    for (let i = 0; i < 5; i++) {
      const valId = `validator-0${i + 1}`;
      const jrnPath = path.join(testDir, `${valId}_journal.wdbjrn`);

      const daemon = new WdbValidatorDaemon({
        validatorId: valId,
        port: 0, // OS assigns available ephemeral port
        host: '127.0.0.1',
        tlsCertPem: pki.validators[i]!.certPem,
        tlsPrivPem: pki.validators[i]!.privPem,
        caPem: pki.ca.certPem,
        ed25519PrivKey: valKeypairs[i]!.privateKey,
        validatorSetManager: valSetManager,
        journalPath: jrnPath,
        expectedAgentPubkey: agentPubkey,
        expectedCustomerPubkey: customerPubkey,
      });

      const port = await daemon.start();
      validatorDaemons.push(daemon);
      validatorPorts.push(port);
    }

    // 2. Start Gateway daemon pointing to validator ports
    const valEndpoints = validatorPorts.map((port, idx) => ({
      validatorId: `validator-0${idx + 1}`,
      url: `https://127.0.0.1:${port}`,
    }));

    gatewayDaemon = new WdbGatewayDaemon({
      port: 0,
      host: '127.0.0.1',
      tlsCertPem: pki.gateway.certPem,
      tlsPrivPem: pki.gateway.privPem,
      caPem: pki.ca.certPem,
      validatorEndpoints: valEndpoints,
      validatorSetManager: valSetManager,
    });

    gatewayPort = await gatewayDaemon.start();

    // 3. Start Agent daemon
    const custSigner = new SoftwareCustomerSigner('cust-root-key', customerKeypair.privateKey);

    agentDaemon = new WdbAgentDaemon({
      agentNodeId: 'agent-vpc-node-01',
      tenantId: 'enterprise_fintech',
      databaseId: 'core_ledger',
      tlsCertPem: pki.agent.certPem,
      tlsPrivPem: pki.agent.privPem,
      caPem: pki.ca.certPem,
      gatewayUrl: `https://127.0.0.1:${gatewayPort}`,
      agentPrivKey: agentKeypair.privateKey,
      customerSigner: custSigner,
    });
  });

  afterAll(async () => {
    if (agentDaemon) await agentDaemon.close();
    if (gatewayDaemon) await gatewayDaemon.stop();
    for (const v of validatorDaemons) {
      await v.stop();
    }
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('1. Full Cluster Witnessing Pipeline: Agent -> mTLS -> Gateway -> 5 Validator Daemons -> 4/5 QC -> Zero-Trust Verification', async () => {
    // Bootstrap initial state
    const snapshot: BootstrapSnapshot = {
      snapshotId: 'snap-cluster-001',
      snapshotLsn: '0/1000000',
      createdAtUs: 1723800000000000n,
      schemaEpoch: 1,
      tables: ['public.accounts'],
      rows: [
        {
          tableName: 'public.accounts',
          primaryKeyFields: [{ name: 'id', typeTag: 5, valueBuffer: Buffer.from('acc_alpha', 'utf8') }],
          values: { id: 'acc_alpha', balance: '50000.00' },
        },
      ],
      initialStateMerkleRoot: Buffer.alloc(32, 0),
    };

    agentDaemon.bootstrap(snapshot);
    const root1 = agentDaemon.stateFrontier.computeStateMerkleRoot();

    // Witness Commit #1
    const qc1 = await agentDaemon.commitAndWitness(
      crypto.createHash('sha256').update('chk_1').digest('hex'),
      root1.toString('hex'),
      crypto.createHash('sha256').update('chain_1').digest('hex'),
      '0/1100000'
    );

    expect(qc1.commitSeq).toBe(1n);
    expect(qc1.quorumCount).toBe(5);
    expect(qc1.certificateVersion).toBe(2);

    // Independent verification of QC1
    const verified1 = IndependentQuorumVerifier.verify(qc1, valSetManager);
    expect(verified1.valid).toBe(true);
    expect(verified1.verifiedSignatures).toBe(5);

    // Witness Commit #2 (Contiguous sequence linking to QC1)
    const qc2 = await agentDaemon.commitAndWitness(
      crypto.createHash('sha256').update('chk_2').digest('hex'),
      root1.toString('hex'),
      crypto.createHash('sha256').update('chain_2').digest('hex'),
      '0/1200000'
    );

    expect(qc2.commitSeq).toBe(2n);
    expect(qc2.quorumCount).toBe(5);

    const verified2 = IndependentQuorumVerifier.verify(qc2, valSetManager);
    expect(verified2.valid).toBe(true);

    // Gateway serves cached receipt for seq 2
    const fetchedReceipt = gatewayDaemon.getReceipt(2n);
    expect(fetchedReceipt).toBeDefined();
    expect(fetchedReceipt?.certificateDigestHex).toBe(qc2.certificateDigestHex);
  });
});
