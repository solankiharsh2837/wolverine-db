export const anchorRegistryAbi = [
  {
    inputs: [
      { internalType: 'uint64', name: 'epoch', type: 'uint64' },
      { internalType: 'uint64', name: 'startSeq', type: 'uint64' },
      { internalType: 'uint64', name: 'endSeq', type: 'uint64' },
      { internalType: 'bytes32', name: 'batchRoot', type: 'bytes32' },
      { internalType: 'bytes32', name: 'previousBatchRoot', type: 'bytes32' },
    ],
    name: 'anchorBatch',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
] as const;
