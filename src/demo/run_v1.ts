import { runV1AdversarialDemo } from './v1_adversarial_demo.js';

runV1AdversarialDemo().catch((err) => {
  console.error('v1.0 Demo execution failed:', err);
  process.exit(1);
});
