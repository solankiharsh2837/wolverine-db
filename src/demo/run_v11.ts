import { runCollusionDefenseDemo } from './collusion_defense_demo.js';

runCollusionDefenseDemo().catch((err) => {
  console.error('v1.1 Demo execution failed:', err);
  process.exit(1);
});
