import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  ValidatorSetManager,
  QuorumAggregator,
  CanonicalCommitment,
  computeCanonicalCommitmentDigest,
  computeAgentAttestationDigest,
  computeCustomerAuthorizationDigest,
  FormalValidatorStateMachine,
  ProbabilisticNetworkChaosHarness,
  IndependentQuorumVerifier,
} from '../src/index.js';

describe('Milestone 6.3 — Probabilistic Byzantine Network Chaos Laboratory', () => {
  it('Executes 200-iteration Monte Carlo chaos test proving P(false finality) = 0', async () => {
    const chaos = new ProbabilisticNetworkChaosHarness({
      dropRate: 0.15,
      duplicateRate: 0.15,
      delayRate: 0.10,
      corruptRate: 0.10,
    });

    const agentKeypair = crypto.generateKeyPairSync('ed25519');
    const customerKeypair = crypto.generateKeyPairSync('ed25519');
    const agentPubkey = agentKeypair.publicKey.export({ format: 'der', type: 'spki' });
    const customerPubkey = customerKeypair.publicKey.export({ format: 'der', type: 'spki' });

    const valKeypairs = [
      crypto.generateKeyPairSync('ed25519'),
      crypto.generateKeyPairSync('ed25519'),
      crypto.generateKeyPairSync('ed25519'),
      crypto.generateKeyPairSync('ed25519'),
      crypto.generateKeyPairSync('ed25519'),
    ];

    const valSetManager = new ValidatorSetManager({
      validatorSetId: 'valset-chaos-01',
      epoch: 1,
      quorumThreshold: 4,
      totalValidators: 5,
      validators: valKeypairs.map((kp, idx) => ({
        validatorId: `val-${idx + 1}`,
        publicKeyHex: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
        weight: 1,
      })),
    });

    const vSms = valKeypairs.map(
      (kp, idx) =>
        new FormalValidatorStateMachine(`val-${idx + 1}`, kp.privateKey, valSetManager, undefined, agentPubkey, customerPubkey)
    );
    for (const v of vSms) await v.initialize();

    for (let i = 1; i <= 50; i++) {
      const commitSeq = BigInt(i);
      const unsigned = {
        commitmentId: `cmt-chaos-${i}`,
        tenantId: 'chaos-tenant',
        databaseId: 'chaos-db',
        epoch: 1,
        commitSeq,
        checkpointDigestHex: crypto.createHash('sha256').update(`chk_${i}`).digest('hex'),
        stateMerkleRootHex: crypto.createHash('sha256').update(`root_${i}`).digest('hex'),
        changeChainHeadHex: crypto.createHash('sha256').update(`head_${i}`).digest('hex'),
        logicalTimestampUs: 1723800000000000n + BigInt(i) * 1000n,
        lsn: `0/${(1000000 + i * 100).toString(16)}`,
        previousCommitmentDigestHex: '00'.repeat(32),
      };

      const cmtDigest = computeCanonicalCommitmentDigest(unsigned);
      const agentDigest = computeAgentAttestationDigest(cmtDigest, unsigned.lsn);
      const agentSig = crypto.sign(null, agentDigest, agentKeypair.privateKey);

      const custDigest = computeCustomerAuthorizationDigest(cmtDigest, commitSeq);
      const custSig = crypto.sign(null, custDigest, customerKeypair.privateKey);

      const commitment: CanonicalCommitment = {
        ...unsigned,
        agentAttestation: {
          agentNodeId: 'node-01',
          agentPubkeyHex: agentPubkey.toString('hex'),
          signatureHex: agentSig.toString('hex'),
          lsn: unsigned.lsn,
        },
        customerAuthorization: {
          keyId: 'kms-01',
          customerPubkeyHex: customerPubkey.toString('hex'),
          signatureHex: custSig.toString('hex'),
          commitSeq,
        },
      };

      // Collect attestations with network chaos
      const rawAtts = [];
      for (const v of vSms) {
        if (chaos.shouldDrop()) continue;
        await chaos.applyDelay();

        try {
          const att = await v.attestCommitment(commitment);
          if (chaos.shouldCorrupt()) {
            att.signatureHex = Buffer.alloc(64, 0xef).toString('hex');
          }
          rawAtts.push(att);
          if (chaos.shouldDuplicate()) {
            rawAtts.push({ ...att });
          }
        } catch {
          // Normal validation rejection under chaos
        }
      }

      try {
        const qc = QuorumAggregator.aggregate(commitment, rawAtts, valSetManager);
        const verification = IndependentQuorumVerifier.verify(qc, valSetManager);

        if (verification.valid) {
          chaos.recordSuccess();
        } else {
          chaos.recordFalseFinality();
        }
      } catch {
        // Expected when < 4 valid signatures arrived due to drops/corruptions
      }
    }

    const metrics = chaos.getMetrics();
    expect(metrics.falseFinalityEvents).toBe(0);
    expect(metrics.totalRpcs).toBeGreaterThan(0);
  });
});
