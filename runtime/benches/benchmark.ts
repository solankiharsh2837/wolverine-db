import { runWithContext, getCurrentContext, buildAuthorizationEnvelope } from '../src/context/index.js';
import { wolverineHttpMiddleware, wrapPgQuery } from '../src/observer/index.js';
import { IncidentEngine } from '../src/incidents/index.js';

function formatMs(startNs: bigint): string {
  const diffNs = process.hrtime.bigint() - startNs;
  return (Number(diffNs) / 1e6).toFixed(3) + ' ms';
}

function runRuntimeBenchmarks() {
  console.log('====================================================');
  console.log('  Wolverine Runtime (.js / .ts) v0.1-rc1 Benchmarks');
  console.log('====================================================\n');

  const N_OPS = 100_000;

  // 1. AsyncLocalStorage Context Establishment Benchmark
  const startContext = process.hrtime.bigint();
  for (let i = 0; i < N_OPS; i++) {
    runWithContext({ actorId: `user_${i}`, sessionId: `sess_${i}` }, () => {
      const _ctx = getCurrentContext();
    });
  }
  const contextDurationNs = process.hrtime.bigint() - startContext;
  const contextTime = formatMs(startContext);
  const contextTps = Math.round(N_OPS / (Number(contextDurationNs) / 1e9));

  console.log(`[1] AsyncLocalStorage Context Establishment (${N_OPS.toLocaleString()} ops):`);
  console.log(`    Total Time: ${contextTime}`);
  console.log(`    Throughput: ${contextTps.toLocaleString()} contexts/sec`);
  console.log(`    Avg Latency: ${((Number(contextDurationNs) / 1e6) / N_OPS * 1000).toFixed(3)} μs/op`);

  // 2. AuthorizationEnvelope Construction Benchmark
  const startEnvelope = process.hrtime.bigint();
  runWithContext({ actorId: 'admin_user', ticketId: 'CHG-100', reason: 'Routine Maintenance' }, () => {
    for (let i = 0; i < N_OPS; i++) {
      const _env = buildAuthorizationEnvelope();
    }
  });
  const envelopeDurationNs = process.hrtime.bigint() - startEnvelope;
  const envelopeTime = formatMs(startEnvelope);
  const envelopeTps = Math.round(N_OPS / (Number(envelopeDurationNs) / 1e9));

  console.log(`\n[2] AuthorizationEnvelope Serialization (${N_OPS.toLocaleString()} ops):`);
  console.log(`    Total Time: ${envelopeTime}`);
  console.log(`    Throughput: ${envelopeTps.toLocaleString()} envelopes/sec`);
  console.log(`    Avg Latency: ${((Number(envelopeDurationNs) / 1e6) / N_OPS * 1000).toFixed(3)} μs/op`);

  // 3. HTTP Middleware Interception Benchmark
  const req = { headers: { 'x-actor-id': 'alice', 'x-session-id': 's123' } };
  const res = { setHeader() {} };
  const startMiddleware = process.hrtime.bigint();
  for (let i = 0; i < N_OPS; i++) {
    wolverineHttpMiddleware(req, res, () => {});
  }
  const middlewareDurationNs = process.hrtime.bigint() - startMiddleware;
  const middlewareTime = formatMs(startMiddleware);
  const middlewareTps = Math.round(N_OPS / (Number(middlewareDurationNs) / 1e9));

  console.log(`\n[3] HTTP Middleware Interception (${N_OPS.toLocaleString()} ops):`);
  console.log(`    Total Time: ${middlewareTime}`);
  console.log(`    Throughput: ${middlewareTps.toLocaleString()} reqs/sec`);

  // 4. Incident Report Creation Benchmark
  const N_INCIDENTS = 50_000;
  const startIncident = process.hrtime.bigint();
  for (let i = 0; i < N_INCIDENTS; i++) {
    IncidentEngine.createReport('SUSPICIOUS', 'QUERY_ANOMALY', { idx: i });
  }
  const incidentDurationNs = process.hrtime.bigint() - startIncident;
  const incidentTime = formatMs(startIncident);
  const incidentTps = Math.round(N_INCIDENTS / (Number(incidentDurationNs) / 1e9));

  console.log(`\n[4] Incident Report Creation (${N_INCIDENTS.toLocaleString()} ops):`);
  console.log(`    Total Time: ${incidentTime}`);
  console.log(`    Throughput: ${incidentTps.toLocaleString()} reports/sec`);

  console.log('\n====================================================\n');
}

runRuntimeBenchmarks();
