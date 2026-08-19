import { runBesuDemo } from './besu_demo.js';

runBesuDemo()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error('Fatal demo execution failure:', err);
    process.exit(1);
  });
