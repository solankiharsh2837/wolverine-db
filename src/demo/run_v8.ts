import { runTrustNetworkDemo } from './trust_network_demo.js';

runTrustNetworkDemo().catch((err) => {
  console.error('v0.8 Demo execution failed:', err);
  process.exit(1);
});
