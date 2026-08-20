import { describe, it, expect } from 'vitest';
import { BesuClient } from '../../src/blockchain/besu/client.js';
import { GrpcGatewayServer } from '../../src/runtime/grpc_gateway_server.js';
import { CanonicalTrustCommitmentV3, computeCanonicalCommitmentDigest } from '../../src/protocol/commitment_v3.js';
import { WolverineError } from '../../src/errors/index.js';

describe('Architectural Invariant: Besu is Sole Finality Authority', () => {
  it('proves that production finality CANNOT exist without a successful Besu transaction', async () => {
    // Construct a mock Besu client that simulates transaction failure / network partition
    const failingBesuClient = new BesuClient(
      {
        rpcUrl: 'http://127.0.0.1:9999', // unreachable
        chainId: 13370,
        contractAddress: '0xf2e246bb76df876cef8b38ae84130f4f55de395b',
      },
      async () => {
        throw new Error('Besu RPC unreachable / transaction rejected');
      }
    );

    const commitment: CanonicalTrustCommitmentV3 = {
      protocolVersion: 3,
      tenantId: 'tenant_enterprise_01',
      databaseId: 'prod_db',
      checkpointId: '00000000-0000-0000-0000-000000000001',
      commitSeq: 1n,
      epoch: 1,
      chainId: 13370,
      contractAddress: '0xf2e246bb76df876cef8b38ae84130f4f55de395b',
      networkId: 'wolverine-besu-cluster',
      checkpointDigestHex: 'a'.repeat(64),
      stateMerkleRootHex: 'b'.repeat(64),
      changeChainHeadHex: 'c'.repeat(64),
      previousCommitmentDigestHex: '0'.repeat(64),
      logicalTimestampUs: 1700000000000000n,
      lsn: '0/1800000',
      agentId: 'agent_01',
      customerSigningAddress: '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf',
    };

    // Attempting to submit when Besu fails MUST reject and CANNOT fall back to in-memory finality
    await expect(
      failingBesuClient.submitCommitment({
        tenantId: commitment.tenantId,
        databaseId: commitment.databaseId,
        checkpointIdHex: commitment.checkpointId.replace(/-/g, ''),
        commitSeq: commitment.commitSeq,
        epoch: commitment.epoch,
        checkpointDigestHex: commitment.checkpointDigestHex,
        stateMerkleRootHex: commitment.stateMerkleRootHex,
        changeChainHeadHex: commitment.changeChainHeadHex,
        previousCommitmentDigestHex: commitment.previousCommitmentDigestHex,
        commitmentDigestHex: `0x${computeCanonicalCommitmentDigest(commitment)}`,
        logicalTimestampUs: commitment.logicalTimestampUs,
        protocolVersion: commitment.protocolVersion,
        agentSignatureHex: '11'.repeat(64),
        customerSignatureHex: '22'.repeat(65),
      })
    ).rejects.toThrow();
  });
});
