export const WOLVERINE_TRUST_REGISTRY_ABI = [
  {
    "inputs": [],
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "commitmentDigest",
        "type": "bytes32"
      }
    ],
    "name": "DuplicateCommitment",
    "type": "error"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "recoveredSigner",
        "type": "address"
      },
      {
        "internalType": "address",
        "name": "expectedSigner",
        "type": "address"
      }
    ],
    "name": "InvalidCustomerSignature",
    "type": "error"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "expected",
        "type": "bytes32"
      },
      {
        "internalType": "bytes32",
        "name": "received",
        "type": "bytes32"
      }
    ],
    "name": "InvalidDigestBinding",
    "type": "error"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "expected",
        "type": "bytes32"
      },
      {
        "internalType": "bytes32",
        "name": "received",
        "type": "bytes32"
      }
    ],
    "name": "InvalidPreviousCommitment",
    "type": "error"
  },
  {
    "inputs": [
      {
        "internalType": "uint64",
        "name": "expected",
        "type": "uint64"
      },
      {
        "internalType": "uint64",
        "name": "received",
        "type": "uint64"
      }
    ],
    "name": "SequenceGapDetected",
    "type": "error"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "tenantId",
        "type": "string"
      }
    ],
    "name": "TenantAlreadyRegistered",
    "type": "error"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "tenantId",
        "type": "string"
      }
    ],
    "name": "TenantNotRegistered",
    "type": "error"
  },
  {
    "inputs": [],
    "name": "Unauthorized",
    "type": "error"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "caller",
        "type": "address"
      },
      {
        "internalType": "address",
        "name": "authorizedGateway",
        "type": "address"
      }
    ],
    "name": "UnauthorizedGateway",
    "type": "error"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "string",
        "name": "tenantId",
        "type": "string"
      },
      {
        "indexed": true,
        "internalType": "string",
        "name": "databaseId",
        "type": "string"
      },
      {
        "indexed": true,
        "internalType": "uint64",
        "name": "commitSeq",
        "type": "uint64"
      },
      {
        "indexed": false,
        "internalType": "bytes32",
        "name": "commitmentDigest",
        "type": "bytes32"
      },
      {
        "indexed": false,
        "internalType": "bytes32",
        "name": "stateMerkleRoot",
        "type": "bytes32"
      },
      {
        "indexed": false,
        "internalType": "bytes32",
        "name": "changeChainHead",
        "type": "bytes32"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "blockNumber",
        "type": "uint256"
      }
    ],
    "name": "CommitmentRecorded",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "uint32",
        "name": "oldEpoch",
        "type": "uint32"
      },
      {
        "indexed": true,
        "internalType": "uint32",
        "name": "newEpoch",
        "type": "uint32"
      }
    ],
    "name": "EpochChanged",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "bytes32",
        "name": "batchDigest",
        "type": "bytes32"
      },
      {
        "indexed": false,
        "internalType": "uint64",
        "name": "startSeq",
        "type": "uint64"
      },
      {
        "indexed": false,
        "internalType": "uint64",
        "name": "endSeq",
        "type": "uint64"
      },
      {
        "indexed": false,
        "internalType": "string",
        "name": "publicChainId",
        "type": "string"
      },
      {
        "indexed": false,
        "internalType": "bytes32",
        "name": "publicTxHash",
        "type": "bytes32"
      }
    ],
    "name": "OptionalAnchorRecorded",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "string",
        "name": "tenantId",
        "type": "string"
      },
      {
        "indexed": true,
        "internalType": "address",
        "name": "customerSigningAddress",
        "type": "address"
      },
      {
        "indexed": true,
        "internalType": "address",
        "name": "authorizedGateway",
        "type": "address"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "blockNumber",
        "type": "uint256"
      }
    ],
    "name": "TenantRegistered",
    "type": "event"
  },
  {
    "inputs": [
      {
        "internalType": "uint32",
        "name": "newEpoch",
        "type": "uint32"
      }
    ],
    "name": "advanceEpoch",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "tenantId",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "databaseId",
        "type": "string"
      },
      {
        "internalType": "bytes16",
        "name": "checkpointId",
        "type": "bytes16"
      },
      {
        "internalType": "uint64",
        "name": "commitSeq",
        "type": "uint64"
      },
      {
        "internalType": "uint32",
        "name": "epoch",
        "type": "uint32"
      },
      {
        "internalType": "bytes32",
        "name": "checkpointDigest",
        "type": "bytes32"
      },
      {
        "internalType": "bytes32",
        "name": "stateMerkleRoot",
        "type": "bytes32"
      },
      {
        "internalType": "bytes32",
        "name": "changeChainHead",
        "type": "bytes32"
      },
      {
        "internalType": "bytes32",
        "name": "previousCommitmentDigest",
        "type": "bytes32"
      },
      {
        "internalType": "bytes32",
        "name": "commitmentDigest",
        "type": "bytes32"
      },
      {
        "internalType": "uint64",
        "name": "logicalTimestampUs",
        "type": "uint64"
      },
      {
        "internalType": "uint16",
        "name": "protocolVersion",
        "type": "uint16"
      },
      {
        "internalType": "bytes",
        "name": "agentSignature",
        "type": "bytes"
      },
      {
        "internalType": "bytes",
        "name": "customerSignature",
        "type": "bytes"
      }
    ],
    "name": "commitState",
    "outputs": [
      {
        "internalType": "bool",
        "name": "",
        "type": "bool"
      }
    ],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "currentEpoch",
    "outputs": [
      {
        "internalType": "uint32",
        "name": "",
        "type": "uint32"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "commitmentDigest",
        "type": "bytes32"
      }
    ],
    "name": "getCommitment",
    "outputs": [
      {
        "components": [
          {
            "internalType": "string",
            "name": "tenantId",
            "type": "string"
          },
          {
            "internalType": "string",
            "name": "databaseId",
            "type": "string"
          },
          {
            "internalType": "bytes16",
            "name": "checkpointId",
            "type": "bytes16"
          },
          {
            "internalType": "uint64",
            "name": "commitSeq",
            "type": "uint64"
          },
          {
            "internalType": "uint32",
            "name": "epoch",
            "type": "uint32"
          },
          {
            "internalType": "bytes32",
            "name": "checkpointDigest",
            "type": "bytes32"
          },
          {
            "internalType": "bytes32",
            "name": "stateMerkleRoot",
            "type": "bytes32"
          },
          {
            "internalType": "bytes32",
            "name": "changeChainHead",
            "type": "bytes32"
          },
          {
            "internalType": "bytes32",
            "name": "previousCommitmentDigest",
            "type": "bytes32"
          },
          {
            "internalType": "bytes32",
            "name": "commitmentDigest",
            "type": "bytes32"
          },
          {
            "internalType": "uint64",
            "name": "logicalTimestampUs",
            "type": "uint64"
          },
          {
            "internalType": "uint16",
            "name": "protocolVersion",
            "type": "uint16"
          },
          {
            "internalType": "bytes",
            "name": "agentSignature",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "customerSignature",
            "type": "bytes"
          },
          {
            "internalType": "uint256",
            "name": "blockNumber",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "blockTimestamp",
            "type": "uint256"
          }
        ],
        "internalType": "struct WolverineTrustRegistry.StateCommitment",
        "name": "",
        "type": "tuple"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "tenantId",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "databaseId",
        "type": "string"
      },
      {
        "internalType": "uint64",
        "name": "commitSeq",
        "type": "uint64"
      }
    ],
    "name": "getCommitmentBySequence",
    "outputs": [
      {
        "components": [
          {
            "internalType": "string",
            "name": "tenantId",
            "type": "string"
          },
          {
            "internalType": "string",
            "name": "databaseId",
            "type": "string"
          },
          {
            "internalType": "bytes16",
            "name": "checkpointId",
            "type": "bytes16"
          },
          {
            "internalType": "uint64",
            "name": "commitSeq",
            "type": "uint64"
          },
          {
            "internalType": "uint32",
            "name": "epoch",
            "type": "uint32"
          },
          {
            "internalType": "bytes32",
            "name": "checkpointDigest",
            "type": "bytes32"
          },
          {
            "internalType": "bytes32",
            "name": "stateMerkleRoot",
            "type": "bytes32"
          },
          {
            "internalType": "bytes32",
            "name": "changeChainHead",
            "type": "bytes32"
          },
          {
            "internalType": "bytes32",
            "name": "previousCommitmentDigest",
            "type": "bytes32"
          },
          {
            "internalType": "bytes32",
            "name": "commitmentDigest",
            "type": "bytes32"
          },
          {
            "internalType": "uint64",
            "name": "logicalTimestampUs",
            "type": "uint64"
          },
          {
            "internalType": "uint16",
            "name": "protocolVersion",
            "type": "uint16"
          },
          {
            "internalType": "bytes",
            "name": "agentSignature",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "customerSignature",
            "type": "bytes"
          },
          {
            "internalType": "uint256",
            "name": "blockNumber",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "blockTimestamp",
            "type": "uint256"
          }
        ],
        "internalType": "struct WolverineTrustRegistry.StateCommitment",
        "name": "",
        "type": "tuple"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "tenantId",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "databaseId",
        "type": "string"
      }
    ],
    "name": "getLatestCommitment",
    "outputs": [
      {
        "components": [
          {
            "internalType": "string",
            "name": "tenantId",
            "type": "string"
          },
          {
            "internalType": "string",
            "name": "databaseId",
            "type": "string"
          },
          {
            "internalType": "bytes16",
            "name": "checkpointId",
            "type": "bytes16"
          },
          {
            "internalType": "uint64",
            "name": "commitSeq",
            "type": "uint64"
          },
          {
            "internalType": "uint32",
            "name": "epoch",
            "type": "uint32"
          },
          {
            "internalType": "bytes32",
            "name": "checkpointDigest",
            "type": "bytes32"
          },
          {
            "internalType": "bytes32",
            "name": "stateMerkleRoot",
            "type": "bytes32"
          },
          {
            "internalType": "bytes32",
            "name": "changeChainHead",
            "type": "bytes32"
          },
          {
            "internalType": "bytes32",
            "name": "previousCommitmentDigest",
            "type": "bytes32"
          },
          {
            "internalType": "bytes32",
            "name": "commitmentDigest",
            "type": "bytes32"
          },
          {
            "internalType": "uint64",
            "name": "logicalTimestampUs",
            "type": "uint64"
          },
          {
            "internalType": "uint16",
            "name": "protocolVersion",
            "type": "uint16"
          },
          {
            "internalType": "bytes",
            "name": "agentSignature",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "customerSignature",
            "type": "bytes"
          },
          {
            "internalType": "uint256",
            "name": "blockNumber",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "blockTimestamp",
            "type": "uint256"
          }
        ],
        "internalType": "struct WolverineTrustRegistry.StateCommitment",
        "name": "",
        "type": "tuple"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "tenantId",
        "type": "string"
      }
    ],
    "name": "getTenant",
    "outputs": [
      {
        "components": [
          {
            "internalType": "address",
            "name": "customerSigningAddress",
            "type": "address"
          },
          {
            "internalType": "address",
            "name": "authorizedGateway",
            "type": "address"
          },
          {
            "internalType": "bool",
            "name": "isRegistered",
            "type": "bool"
          },
          {
            "internalType": "uint64",
            "name": "registeredAtBlock",
            "type": "uint64"
          }
        ],
        "internalType": "struct WolverineTrustRegistry.TenantConfig",
        "name": "",
        "type": "tuple"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "owner",
    "outputs": [
      {
        "internalType": "address",
        "name": "",
        "type": "address"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "batchDigest",
        "type": "bytes32"
      },
      {
        "internalType": "uint64",
        "name": "startSeq",
        "type": "uint64"
      },
      {
        "internalType": "uint64",
        "name": "endSeq",
        "type": "uint64"
      },
      {
        "internalType": "string",
        "name": "publicChainId",
        "type": "string"
      },
      {
        "internalType": "bytes32",
        "name": "publicTxHash",
        "type": "bytes32"
      }
    ],
    "name": "recordOptionalAnchor",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "tenantId",
        "type": "string"
      },
      {
        "internalType": "address",
        "name": "customerSigningAddress",
        "type": "address"
      },
      {
        "internalType": "address",
        "name": "authorizedGateway",
        "type": "address"
      }
    ],
    "name": "registerTenant",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
] as const;
