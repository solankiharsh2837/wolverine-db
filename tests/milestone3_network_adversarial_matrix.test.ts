import { describe, it, expect, beforeEach, afterEach } from 'vitest';
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
  MtlsClient,
  CanonicalCommitment,
  computeCanonicalCommitmentDigest,
  computeAgentAttestationDigest,
  computeCustomerAuthorizationDigest,
} from '../src/index.js';

describe('Milestone 3.4, 3.5, 3.6 & 3.8 — Distributed Network Adversarial & Chaos Matrix', () => {
  const testDir = path.join(process.cwd(), 'tmp', 'test_m3_chaos');
  const pki = generateClusterTlsPki();

  const agentKeypair = crypto.generateKeyPairSync('ed25519');
  const customerKeypair = crypto.generateKeyPairSync('ed25519');
  const valKeypairs = [
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
    crypto.generateKeyPairSync('ed25519'),
  ];

  const agentPubkey = agentKeypair.publicKey.export({ format: 'der', type: 'spki' });
  const customerPubkey = customerKeypair.publicKey.export({ format: 'der', type: 'spki' });

  const valNodes = valKeypairs.map((kp, idx) => ({
    validatorId: `validator-0${idx + 1}`,
    publicKeyHex: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
    weight: 1,
  }));

  const valSetManager = new ValidatorSetManager({
    validatorSetId: 'valset-cluster-chaos',
    epoch: 1,
    quorumThreshold: 4,
    totalValidators: 5,
    validators: valNodes,
  });

  beforeEach(() => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  function makeCommitment(
    seq: bigint,
    customTag: string = 'REAL',
    prevDigestHex: string = '0000000000000000000000000000000000000000000000000000000000000000'
  ): CanonicalCommitment {
    const unsigned = {
      commitmentId: `cmt-${seq}-${customTag}`,
      tenantId: 'enterprise_bank',
      databaseId: 'core_ledger',
      epoch: 1,
      commitSeq: seq,
      checkpointDigestHex: crypto.createHash('sha256').update(`chk_${seq}_${customTag}`).digest('hex'),
      stateMerkleRootHex: crypto.createHash('sha256').update(`root_${seq}_${customTag}`).digest('hex'),
      changeChainHeadHex: crypto.createHash('sha256').update(`chain_${seq}_${customTag}`).digest('hex'),
      logicalTimestampUs: 1723800000000000n + seq * 1000000n,
      lsn: `0/${(1600000n + seq * 100n).toString(16)}`,
      previousCommitmentDigestHex: prevDigestHex,
    };

    const cmtDigest = computeCanonicalCommitmentDigest(unsigned);
    const agentDigest = computeAgentAttestationDigest(cmtDigest, unsigned.lsn);
    const agentSig = crypto.sign(null, agentDigest, agentKeypair.privateKey);
    const custDigest = computeCustomerAuthorizationDigest(cmtDigest, seq);
    const custSig = crypto.sign(null, custDigest, customerKeypair.privateKey);

    return {
      ...unsigned,
      agentAttestation: {
        agentNodeId: 'agent-vpc-01',
        agentPubkeyHex: agentPubkey.toString('hex'),
        signatureHex: agentSig.toString('hex'),
        lsn: unsigned.lsn,
      },
      customerAuthorization: {
        keyId: 'kms-root-01',
        customerPubkeyHex: customerPubkey.toString('hex'),
        signatureHex: custSig.toString('hex'),
        commitSeq: seq,
      },
    };
  }

  it('1. Gateway Network Partition: partition leaving 2/5 validators reachable fails closed without QC', async () => {
    // Start only 2 validators (V1, V2)
    const v1 = new WdbValidatorDaemon({
      validatorId: 'validator-01',
      port: 0,
      tlsCertPem: pki.validators[0]!.certPem,
      tlsPrivPem: pki.validators[0]!.privPem,
      caPem: pki.ca.certPem,
      ed25519PrivKey: valKeypairs[0]!.privateKey,
      validatorSetManager: valSetManager,
      expectedAgentPubkey: agentPubkey,
      expectedCustomerPubkey: customerPubkey,
    });
    const v2 = new WdbValidatorDaemon({
      validatorId: 'validator-02',
      port: 0,
      tlsCertPem: pki.validators[1]!.certPem,
      tlsPrivPem: pki.validators[1]!.privPem,
      caPem: pki.ca.certPem,
      ed25519PrivKey: valKeypairs[1]!.privateKey,
      validatorSetManager: valSetManager,
      expectedAgentPubkey: agentPubkey,
      expectedCustomerPubkey: customerPubkey,
    });

    const p1 = await v1.start();
    const p2 = await v2.start();

    // Gateway configured with 5 endpoints, but V3, V4, V5 are offline (partitioned)
    const gateway = new WdbGatewayDaemon({
      port: 0,
      tlsCertPem: pki.gateway.certPem,
      tlsPrivPem: pki.gateway.privPem,
      caPem: pki.ca.certPem,
      validatorEndpoints: [
        { validatorId: 'validator-01', url: `https://127.0.0.1:${p1}` },
        { validatorId: 'validator-02', url: `https://127.0.0.1:${p2}` },
        { validatorId: 'validator-03', url: 'https://127.0.0.1:59993' }, // OFFLINE
        { validatorId: 'validator-04', url: 'https://127.0.0.1:59994' }, // OFFLINE
        { validatorId: 'validator-05', url: 'https://127.0.0.1:59995' }, // OFFLINE
      ],
      validatorSetManager: valSetManager,
    });

    const gPort = await gateway.start();

    const agent = new WdbAgentDaemon({
      agentNodeId: 'agent-vpc-01',
      tenantId: 'enterprise_bank',
      databaseId: 'core_ledger',
      tlsCertPem: pki.agent.certPem,
      tlsPrivPem: pki.agent.privPem,
      caPem: pki.ca.certPem,
      gatewayUrl: `https://127.0.0.1:${gPort}`,
      agentPrivKey: agentKeypair.privateKey,
      customerSigner: new SoftwareCustomerSigner('cust-01', customerKeypair.privateKey),
    });

    // Attempting to commit must fail closed (2/5 signatures < 4 quorum)
    await expect(
      agent.commitAndWitness(
        crypto.createHash('sha256').update('chk_p').digest('hex'),
        crypto.createHash('sha256').update('root_p').digest('hex'),
        crypto.createHash('sha256').update('chain_p').digest('hex'),
        '0/1100000'
      )
    ).rejects.toThrowError(/Gateway failed to achieve quorum/);

    await agent.close();
    await gateway.stop();
    await v1.stop();
    await v2.stop();
  });

  it('2. Validator Crash & Isolation: killing 1 of 5 achieves 4/5 QC; killing 2 of 5 halts finality', async () => {
    const daemons: WdbValidatorDaemon[] = [];
    const ports: number[] = [];

    for (let i = 0; i < 5; i++) {
      const d = new WdbValidatorDaemon({
        validatorId: `validator-0${i + 1}`,
        port: 0,
        tlsCertPem: pki.validators[i]!.certPem,
        tlsPrivPem: pki.validators[i]!.privPem,
        caPem: pki.ca.certPem,
        ed25519PrivKey: valKeypairs[i]!.privateKey,
        validatorSetManager: valSetManager,
        expectedAgentPubkey: agentPubkey,
        expectedCustomerPubkey: customerPubkey,
      });
      ports.push(await d.start());
      daemons.push(d);
    }

    const gateway = new WdbGatewayDaemon({
      port: 0,
      tlsCertPem: pki.gateway.certPem,
      tlsPrivPem: pki.gateway.privPem,
      caPem: pki.ca.certPem,
      validatorEndpoints: ports.map((p, idx) => ({
        validatorId: `validator-0${idx + 1}`,
        url: `https://127.0.0.1:${p}`,
      })),
      validatorSetManager: valSetManager,
    });
    const gPort = await gateway.start();

    const agent = new WdbAgentDaemon({
      agentNodeId: 'agent-vpc-01',
      tenantId: 'enterprise_bank',
      databaseId: 'core_ledger',
      tlsCertPem: pki.agent.certPem,
      tlsPrivPem: pki.agent.privPem,
      caPem: pki.ca.certPem,
      gatewayUrl: `https://127.0.0.1:${gPort}`,
      agentPrivKey: agentKeypair.privateKey,
      customerSigner: new SoftwareCustomerSigner('cust-01', customerKeypair.privateKey),
    });

    // Step A: Kill Validator 5 (4/5 online)
    await daemons[4]!.stop();

    const qc1 = await agent.commitAndWitness(
      crypto.createHash('sha256').update('chk_1').digest('hex'),
      crypto.createHash('sha256').update('root_1').digest('hex'),
      crypto.createHash('sha256').update('chain_1').digest('hex'),
      '0/1100000'
    );
    expect(qc1.quorumCount).toBe(4);
    expect(IndependentQuorumVerifier.verify(qc1, valSetManager).valid).toBe(true);

    // Step B: Kill Validator 4 as well (only 3/5 online)
    await daemons[3]!.stop();

    await expect(
      agent.commitAndWitness(
        crypto.createHash('sha256').update('chk_2').digest('hex'),
        crypto.createHash('sha256').update('root_2').digest('hex'),
        crypto.createHash('sha256').update('chain_2').digest('hex'),
        '0/1200000'
      )
    ).rejects.toThrowError(/Gateway failed to achieve quorum/);

    await agent.close();
    await gateway.stop();
    for (let i = 0; i < 3; i++) {
      await daemons[i]!.stop();
    }
  });

  it('3. Message Duplication: 100 duplicate network requests produce identical signatures and zero state drift', async () => {
    const valDaemon = new WdbValidatorDaemon({
      validatorId: 'validator-01',
      port: 0,
      tlsCertPem: pki.validators[0]!.certPem,
      tlsPrivPem: pki.validators[0]!.privPem,
      caPem: pki.ca.certPem,
      ed25519PrivKey: valKeypairs[0]!.privateKey,
      validatorSetManager: valSetManager,
      expectedAgentPubkey: agentPubkey,
      expectedCustomerPubkey: customerPubkey,
    });
    const port = await valDaemon.start();

    const client = new MtlsClient({
      certPem: pki.agent.certPem,
      privPem: pki.agent.privPem,
      caPem: pki.ca.certPem,
      rejectUnauthorized: true,
    });

    const cmt = makeCommitment(1842n, 'IDEMPOTENT_TEST');
    const serializableCmt = {
      ...cmt,
      commitSeq: cmt.commitSeq.toString(),
      logicalTimestampUs: cmt.logicalTimestampUs.toString(),
      customerAuthorization: {
        ...cmt.customerAuthorization,
        commitSeq: cmt.customerAuthorization.commitSeq.toString(),
      },
    };

    // Send the first request
    const firstRes = await client.request(`https://127.0.0.1:${port}/v1/attest`, 'POST', serializableCmt);
    expect(firstRes.statusCode).toBe(200);
    const expectedSig = firstRes.data.signatureHex;

    // Send 99 duplicate requests concurrently
    const dupePromises = Array.from({ length: 99 }).map(() =>
      client.request(`https://127.0.0.1:${port}/v1/attest`, 'POST', serializableCmt)
    );

    const responses = await Promise.all(dupePromises);
    for (const r of responses) {
      expect(r.statusCode).toBe(200);
      expect(r.data.signatureHex).toBe(expectedSig);
      expect(r.data.commitSeq).toBe('1842');
    }

    // Sequence remains strictly 1842
    expect(valDaemon.getStateMachine().sequence).toBe(1842n);

    await valDaemon.stop();
  });

  it('4. Message Reordering: out-of-order sequence arrivals (1843, 1841) are rejected; expected 1842 succeeds', async () => {
    const valDaemon = new WdbValidatorDaemon({
      validatorId: 'validator-01',
      port: 0,
      tlsCertPem: pki.validators[0]!.certPem,
      tlsPrivPem: pki.validators[0]!.privPem,
      caPem: pki.ca.certPem,
      ed25519PrivKey: valKeypairs[0]!.privateKey,
      validatorSetManager: valSetManager,
      expectedAgentPubkey: agentPubkey,
      expectedCustomerPubkey: customerPubkey,
    });
    const port = await valDaemon.start();

    const client = new MtlsClient({
      certPem: pki.agent.certPem,
      privPem: pki.agent.privPem,
      caPem: pki.ca.certPem,
      rejectUnauthorized: true,
    });

    const cmt1841 = makeCommitment(1841n, 'STATE_1841');
    const cmt1842 = makeCommitment(1842n, 'STATE_1842', computeCanonicalCommitmentDigest(cmt1841).toString('hex'));
    const cmt1843 = makeCommitment(1843n, 'STATE_1843', computeCanonicalCommitmentDigest(cmt1842).toString('hex'));

    const serialize = (c: any) => ({
      ...c,
      commitSeq: c.commitSeq.toString(),
      logicalTimestampUs: c.logicalTimestampUs.toString(),
      customerAuthorization: {
        ...c.customerAuthorization,
        commitSeq: c.customerAuthorization.commitSeq.toString(),
      },
    });

    // Ingest 1841 first to establish head at 1841
    const r1841 = await client.request(`https://127.0.0.1:${port}/v1/attest`, 'POST', serialize(cmt1841));
    expect(r1841.statusCode).toBe(200);

    // 1. Send out-of-order 1843 (gap: expected 1842) -> Rejected
    const r1843 = await client.request(`https://127.0.0.1:${port}/v1/attest`, 'POST', serialize(cmt1843));
    expect(r1843.statusCode).toBe(400);
    expect(r1843.data.code).toBe('WDB309'); // SEQUENCE_GAP_DETECTED

    // 2. Send 1842 (valid contiguous successor) -> Accepted
    const r1842 = await client.request(`https://127.0.0.1:${port}/v1/attest`, 'POST', serialize(cmt1842));
    expect(r1842.statusCode).toBe(200);
    expect(r1842.data.commitSeq).toBe('1842');

    // 3. Send 1841 again with forged digest -> Rejected with EQUIVOCATION
    const cmt1841Forged = makeCommitment(1841n, 'FORGED_1841');
    const r1841Forged = await client.request(`https://127.0.0.1:${port}/v1/attest`, 'POST', serialize(cmt1841Forged));
    expect(r1841Forged.statusCode).toBe(409); // HISTORY_MUTATION_DETECTED / EQUIVOCATION

    await valDaemon.stop();
  });

  it('5. Process-Level Byzantine Simulation: V5 rogue process in WRONG_DIGEST mode is excluded while 4 honest achieve valid QC', async () => {
    const daemons: WdbValidatorDaemon[] = [];
    const ports: number[] = [];

    for (let i = 0; i < 5; i++) {
      const isRogue = i === 4; // Validator 5 is rogue Byzantine
      const d = new WdbValidatorDaemon({
        validatorId: `validator-0${i + 1}`,
        port: 0,
        tlsCertPem: pki.validators[i]!.certPem,
        tlsPrivPem: pki.validators[i]!.privPem,
        caPem: pki.ca.certPem,
        ed25519PrivKey: valKeypairs[i]!.privateKey,
        validatorSetManager: valSetManager,
        expectedAgentPubkey: agentPubkey,
        expectedCustomerPubkey: customerPubkey,
        byzantineMode: isRogue ? 'WRONG_DIGEST' : 'NONE',
      });
      ports.push(await d.start());
      daemons.push(d);
    }

    const gateway = new WdbGatewayDaemon({
      port: 0,
      tlsCertPem: pki.gateway.certPem,
      tlsPrivPem: pki.gateway.privPem,
      caPem: pki.ca.certPem,
      validatorEndpoints: ports.map((p, idx) => ({
        validatorId: `validator-0${idx + 1}`,
        url: `https://127.0.0.1:${p}`,
      })),
      validatorSetManager: valSetManager,
    });
    const gPort = await gateway.start();

    const agent = new WdbAgentDaemon({
      agentNodeId: 'agent-vpc-01',
      tenantId: 'enterprise_bank',
      databaseId: 'core_ledger',
      tlsCertPem: pki.agent.certPem,
      tlsPrivPem: pki.agent.privPem,
      caPem: pki.ca.certPem,
      gatewayUrl: `https://127.0.0.1:${gPort}`,
      agentPrivKey: agentKeypair.privateKey,
      customerSigner: new SoftwareCustomerSigner('cust-01', customerKeypair.privateKey),
    });

    const qc = await agent.commitAndWitness(
      crypto.createHash('sha256').update('chk_byz').digest('hex'),
      crypto.createHash('sha256').update('root_byz').digest('hex'),
      crypto.createHash('sha256').update('chain_byz').digest('hex'),
      '0/1100000'
    );

    // Assert: Quorum certificate aggregated 4 honest signatures, excluding rogue V5
    expect(qc.quorumCount).toBe(4);
    const signedValidatorIds = qc.attestations.map((a) => a.validatorId);
    expect(signedValidatorIds).toContain('validator-01');
    expect(signedValidatorIds).toContain('validator-02');
    expect(signedValidatorIds).toContain('validator-03');
    expect(signedValidatorIds).toContain('validator-04');
    expect(signedValidatorIds).not.toContain('validator-05');

    // Independent verification passes cleanly
    expect(IndependentQuorumVerifier.verify(qc, valSetManager).valid).toBe(true);

    await agent.close();
    await gateway.stop();
    for (const d of daemons) await d.stop();
  });

  it('6. The Important Test: Validator process killed, restarted with replayed journal, rejects conflicting commitment via EQUIVOCATION_DETECTED over mTLS', async () => {
    const journalPath = path.join(testDir, 'v3_persistent_journal.wdbjrn');

    // 1. Start Validator 3 daemon
    let v3 = new WdbValidatorDaemon({
      validatorId: 'validator-03',
      port: 0,
      tlsCertPem: pki.validators[2]!.certPem,
      tlsPrivPem: pki.validators[2]!.privPem,
      caPem: pki.ca.certPem,
      ed25519PrivKey: valKeypairs[2]!.privateKey,
      validatorSetManager: valSetManager,
      journalPath,
      expectedAgentPubkey: agentPubkey,
      expectedCustomerPubkey: customerPubkey,
    });
    let portV3 = await v3.start();

    const client = new MtlsClient({
      certPem: pki.agent.certPem,
      privPem: pki.agent.privPem,
      caPem: pki.ca.certPem,
      rejectUnauthorized: true,
    });

    const cmt1842Honest = makeCommitment(1842n, 'HONEST_STATE_1842');
    const serialize = (c: any) => ({
      ...c,
      commitSeq: c.commitSeq.toString(),
      logicalTimestampUs: c.logicalTimestampUs.toString(),
      customerAuthorization: {
        ...c.customerAuthorization,
        commitSeq: c.customerAuthorization.commitSeq.toString(),
      },
    });

    // 2. Commit C1842 over mTLS HTTP
    const r1 = await client.request(`https://127.0.0.1:${portV3}/v1/attest`, 'POST', serialize(cmt1842Honest));
    expect(r1.statusCode).toBe(200);

    // 3. Kill Validator 3 and wipe its process memory
    await v3.stop();

    // 4. Restart Validator 3 on a new ephemeral port pointing to the same persistent journal file
    v3 = new WdbValidatorDaemon({
      validatorId: 'validator-03',
      port: 0,
      tlsCertPem: pki.validators[2]!.certPem,
      tlsPrivPem: pki.validators[2]!.privPem,
      caPem: pki.ca.certPem,
      ed25519PrivKey: valKeypairs[2]!.privateKey,
      validatorSetManager: valSetManager,
      journalPath,
      expectedAgentPubkey: agentPubkey,
      expectedCustomerPubkey: customerPubkey,
    });
    portV3 = await v3.start();

    // 5. Send conflicting C1842' (different state digest) over network RPC
    const cmt1842Attack = makeCommitment(1842n, 'ATTACK_FORK_1842');
    const rConflicting = await client.request(`https://127.0.0.1:${portV3}/v1/attest`, 'POST', serialize(cmt1842Attack));

    // Must be rejected with HTTP 409 and EQUIVOCATION_DETECTED
    expect(rConflicting.statusCode).toBe(409);
    expect(rConflicting.data.error).toContain('EQUIVOCATION_DETECTED');

    // 6. Resending the original C1842Honest must return the cached attestation
    const rIdempotent = await client.request(`https://127.0.0.1:${portV3}/v1/attest`, 'POST', serialize(cmt1842Honest));
    expect(rIdempotent.statusCode).toBe(200);
    expect(rIdempotent.data.signatureHex).toBe(r1.data.signatureHex);

    await v3.stop();
  });
});
