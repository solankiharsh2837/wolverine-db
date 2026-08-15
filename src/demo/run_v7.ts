import { runContinuousReconstructionDemo } from './continuous_reconstruction_demo.js';

runContinuousReconstructionDemo().catch((err) => {
  console.error('v0.7 Demo execution failed:', err);
  process.exit(1);
});
