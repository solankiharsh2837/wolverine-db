import { runCatastrophicRecoveryDemo } from './catastrophic_recovery_demo.js';

runCatastrophicRecoveryDemo().catch((err) => {
  console.error('v1.2 Demo execution failed:', err);
  process.exit(1);
});
