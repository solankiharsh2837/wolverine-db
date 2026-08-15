import { runDistributedRuntimeDemo } from './distributed_runtime_demo.js';

runDistributedRuntimeDemo().catch((err) => {
  console.error('v0.9 Demo execution failed:', err);
  process.exit(1);
});
