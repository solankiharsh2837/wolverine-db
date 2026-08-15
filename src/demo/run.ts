import { runCinematicReconstructionDemo } from './reconstruction_demo.js';

runCinematicReconstructionDemo().catch((err) => {
  console.error('Demo execution failed:', err);
  process.exit(1);
});
