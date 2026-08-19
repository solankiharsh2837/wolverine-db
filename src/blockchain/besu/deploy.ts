import fs from 'node:fs';
import path from 'node:path';
import {
  createPublicClient,
  createWalletClient,
  http,
  defineChain,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { compileWolverineTrustRegistry } from './compiler.js';

export interface DeploymentMetadata {
  contractName: string;
  contractAddress: `0x${string}`;
  deploymentTxHash: `0x${string}`;
  blockNumber: string;
  blockHash: `0x${string}`;
  chainId: number;
  deployedAt: string;
  deployerAddress: string;
}

export async function deployTrustRegistry(rpcUrl: string = 'http://127.0.0.1:8545'): Promise<DeploymentMetadata> {
  const chainId = 13370;
  const operatorPrivateKeyHex: `0x${string}` =
    '0x0000000000000000000000000000000000000000000000000000000000000001';

  console.log('\n[1/4] Compiling WolverineTrustRegistry.sol from source...');
  const { abi, bytecode } = compileWolverineTrustRegistry();
  console.log(`      ✓ Compiled EVM Bytecode (${bytecode.length} chars, ${abi.length} ABI definitions)`);

  console.log(`\n[2/4] Connecting to Besu QBFT Node at ${rpcUrl}...`);
  const chain = defineChain({
    id: chainId,
    name: 'Wolverine Trust Chain',
    nativeCurrency: { name: 'WGAS', symbol: 'WGAS', decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });

  const publicClient = createPublicClient({
    chain,
    transport: http(rpcUrl, { timeout: 4000 }),
  });

  const deployer = privateKeyToAccount(operatorPrivateKeyHex);
  const walletClient = createWalletClient({
    account: deployer,
    chain,
    transport: http(rpcUrl, { timeout: 4000 }),
  });

  // Verify Besu liveness
  try {
    const blockNum = await publicClient.getBlockNumber();
    console.log(`      ✓ Connected to Besu cluster (Current Block: #${blockNum})`);
  } catch (err: any) {
    console.error('\n❌ REAL BESU NETWORK UNAVAILABLE.');
    console.error('   NO SIMULATION FALLBACK.');
    console.error(`   Failed to connect to ${rpcUrl}: ${err.message}`);
    console.error('   Please run `npm run besu:up` and retry.\n');
    throw new Error(`REAL BESU NETWORK UNAVAILABLE: ${err.message}`);
  }

  console.log('\n[3/4] Broadcasting Contract Deployment Transaction...');
  const deployHash = await walletClient.deployContract({
    abi,
    bytecode,
    account: deployer,
  });
  console.log(`      ✓ Deployment Tx Hash: ${deployHash}`);

  console.log('\n[4/4] Awaiting QBFT Block Inclusion & Finality...');
  const receipt = await publicClient.waitForTransactionReceipt({
    hash: deployHash,
    confirmations: 1,
  });

  if (receipt.status === 'reverted' || !receipt.contractAddress) {
    throw new Error(`Contract deployment transaction reverted on-chain: ${receipt.transactionHash}`);
  }

  // Verify deployed bytecode exists at contractAddress
  const onChainCode = await publicClient.getBytecode({ address: receipt.contractAddress });
  if (!onChainCode || onChainCode === '0x') {
    throw new Error(`Bytecode verification failed at deployed address ${receipt.contractAddress}`);
  }

  const deploymentData: DeploymentMetadata = {
    contractName: 'WolverineTrustRegistry',
    contractAddress: receipt.contractAddress,
    deploymentTxHash: receipt.transactionHash,
    blockNumber: receipt.blockNumber.toString(),
    blockHash: receipt.blockHash,
    chainId,
    deployedAt: new Date().toISOString(),
    deployerAddress: deployer.address,
  };

  const deploymentDir = path.resolve(process.cwd(), 'blockchain', 'besu', 'deployment');
  if (!fs.existsSync(deploymentDir)) {
    fs.mkdirSync(deploymentDir, { recursive: true });
  }

  const deploymentFilePath = path.join(deploymentDir, 'deployment.json');
  fs.writeFileSync(deploymentFilePath, JSON.stringify(deploymentData, null, 2), 'utf8');

  console.log('\n' + '='.repeat(70));
  console.log('  WOLVERINETRUSTREGISTRY SUCCESSFULLY DEPLOYED TO BESU');
  console.log('='.repeat(70));
  console.log(`  Contract Address:   ${deploymentData.contractAddress}`);
  console.log(`  Block Number:       #${deploymentData.blockNumber}`);
  console.log(`  Block Hash:         ${deploymentData.blockHash}`);
  console.log(`  Deployment Tx:      ${deploymentData.deploymentTxHash}`);
  console.log(`  Deployment File:    ${deploymentFilePath}`);
  console.log('='.repeat(70) + '\n');

  return deploymentData;
}

if (process.argv[1]?.endsWith('deploy.js') || process.argv[1]?.endsWith('deploy.ts')) {
  deployTrustRegistry()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err.message);
      process.exit(1);
    });
}
