import fs from 'node:fs';
import path from 'node:path';
import { BesuClient } from './client.js';

export async function checkBesuStatus(rpcUrl: string = 'http://127.0.0.1:8545') {
  const client = new BesuClient({
    rpcUrl,
    chainId: 13370,
    contractAddress: '0x0000000000000000000000000000000000000000',
    timeoutMs: 3000,
  });

  const isOnline = await client.isHealthy();
  let blockNumber = 0n;
  let peerCount = 0;

  if (isOnline) {
    blockNumber = await client.getBlockNumber();
    peerCount = await client.getPeerCount();
  }

  const deploymentPath = path.resolve(process.cwd(), 'blockchain', 'besu', 'deployment', 'deployment.json');
  let contractAddress = 'NOT DEPLOYED';
  let deployedBlock = 'N/A';

  if (fs.existsSync(deploymentPath)) {
    try {
      const data = JSON.parse(fs.readFileSync(deploymentPath, 'utf8'));
      contractAddress = data.contractAddress || 'NOT DEPLOYED';
      deployedBlock = data.blockNumber ? `#${data.blockNumber}` : 'N/A';
    } catch {
      // ignore
    }
  }

  console.log('\n' + '='.repeat(65));
  console.log('          WOLVERINE BESU TRUST NETWORK STATUS');
  console.log('='.repeat(65));
  console.log(`  Chain ID:                  13370 (wolverine-trust-chain)`);
  console.log(`  Consensus:                 QBFT (Quorum Byzantine Fault Tolerance)`);
  console.log(`  Validators configured:     5 Nodes`);
  console.log(`  Network Health:            ${isOnline ? 'ONLINE (HEALTHY)' : 'OFFLINE (UNREACHABLE)'}`);
  console.log(`  Connected Peers:           ${peerCount}`);
  console.log(`  Current Block Height:      ${isOnline ? '#' + blockNumber.toString() : 'N/A'}`);
  console.log(`  Smart Contract Address:    ${contractAddress}`);
  console.log(`  Deployment Block:          ${deployedBlock}`);
  console.log('='.repeat(65) + '\n');

  return {
    isOnline,
    blockNumber,
    peerCount,
    contractAddress,
  };
}

if (process.argv[1]?.endsWith('status.js') || process.argv[1]?.endsWith('status.ts')) {
  checkBesuStatus().catch((err) => {
    console.error('Status check failed:', err.message);
    process.exit(1);
  });
}
