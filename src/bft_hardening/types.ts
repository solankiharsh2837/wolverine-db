import {
  PortableTrustProof,
} from '../trust_network/types.js';

export interface CollusionAttackScenario {
  rogueValidatorId: string;
  isGatewayCompromised: boolean;
  rogueReplicaId: string;
  targetSequence: bigint;
  forgedCheckpointDigest: Buffer;
}

export interface EpochTransitionRecord {
  oldEpoch: number;
  newEpoch: number;
  transitionTimestampUs: bigint;
  previousEpochHeadDigest: Buffer;
  activeValidatorSetId: string;
}

export interface CustomerKeyRotationRecord {
  tenantId: string;
  databaseId: string;
  oldPubkeyHex: string;
  newPubkeyHex: string;
  rotationSeq: bigint;
  oldKeySignatureHex: string;
  newKeySignatureHex: string;
  timestampUs: bigint;
}

export interface ImmutableTrustReceipt {
  receiptVersion: 1;
  receiptId: string;
  tenantId: string;
  databaseId: string;
  databaseTime: {
    checkpointId: string;
    commitSeq: string;
    checkpointDigestHex: string;
  };
  trustTime: {
    ledgerSeq: string;
    epoch: number;
    finalizedAtUs: string;
    merkleStateRootHex: string;
  };
  consensus: {
    validatorSetId: string;
    quorumCount: number;
    totalValidators: number;
    quorumCertificateDigestHex: string;
  };
  portableProof: PortableTrustProof;
  receiptDigestHex: string;
}
