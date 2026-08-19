import { execSync } from 'node:child_process';
import path from 'node:path';
import { checkBesuStatus } from './status.js';

const composeFile = path.resolve(process.cwd(), 'blockchain', 'besu', 'docker-compose.yml');

export function startBesuNetwork() {
  console.log('\n[1/3] Launching 5-Node Hyperledger Besu QBFT Cluster via Docker Compose...');
  try {
    execSync(`docker compose -f "${composeFile}" up -d`, { stdio: 'inherit' });
  } catch (err: any) {
    console.error('\n❌ FAILED TO START DOCKER CONTAINERS.');
    console.error('   Please ensure Docker Desktop is running on this machine.');
    console.error(`   Error: ${err.message}\n`);
    process.exit(1);
  }

  console.log('\n[2/3] Waiting for Besu Nodes to initialize and form QBFT consensus...');
  // Wait up to 10 seconds for RPC to become ready
  let attempts = 0;
  const maxAttempts = 10;

  const interval = setInterval(async () => {
    attempts++;
    try {
      const status = await checkBesuStatus();
      if (status.isOnline) {
        clearInterval(interval);
        console.log('\n[3/3] ✓ Hyperledger Besu QBFT Network is live and healthy!\n');
        process.exit(0);
      }
    } catch {
      // retry
    }

    if (attempts >= maxAttempts) {
      clearInterval(interval);
      console.warn('\n⚠️ Besu network started, but RPC readiness check timed out. Inspect `docker ps` or `npm run besu:status`.\n');
      process.exit(0);
    }
  }, 1000);
}

export function stopBesuNetwork() {
  console.log('\nStopping Hyperledger Besu Cluster...');
  try {
    execSync(`docker compose -f "${composeFile}" down`, { stdio: 'inherit' });
    console.log('✓ Besu Cluster stopped.\n');
  } catch (err: any) {
    console.error('Failed to stop Besu cluster:', err.message);
    process.exit(1);
  }
}

const action = process.argv[2];
if (action === 'up') {
  startBesuNetwork();
} else if (action === 'down') {
  stopBesuNetwork();
}
