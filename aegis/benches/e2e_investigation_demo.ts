import { handleInvestigate } from '../src/cli/commands/investigate.js';
import { handleStatus } from '../src/cli/commands/status.js';

function runE2EInvestigationDemo() {
  console.log('====================================================');
  console.log('  AEGIS Cyber Threat Intelligence Platform (v0.1-rc2)');
  console.log('====================================================\n');

  console.log('>>> Step 1: Self-Protection Integrity Audit (WolverineDB & Runtime)...');
  const status = handleStatus();
  console.log(`    WolverineDB State Protection:  ${status.wolverineDbProtection}`);
  console.log(`    Wolverine Runtime Telemetry:   ${status.wolverineRuntimeStatus}`);
  console.log(`    Protected Storage Tables:      ${status.protectedTables.join(', ')}\n`);

  console.log('>>> Step 2: Launching Automated Investigation for Target "nocturne_operator"...');
  const result = handleInvestigate('nocturne_operator', 'CONTROLLED_LAB_PLANE', 'actor_nocturne_operator');

  console.log('\n====================================================');
  console.log('  EVIDENCE HARVESTED & NORMALIZED');
  console.log('====================================================');
  console.log(`  Evidence Records Collected: ${result.collection.evidenceRecords.length}`);
  result.collection.evidenceRecords.forEach((ev, i) => {
    console.log(`  [${i + 1}] ID: ${ev.evidenceId}`);
    console.log(`      Source: ${ev.sourceType} (${ev.sourceUri})`);
    console.log(`      SHA-256 Digest: 0x${ev.payloadHash.toString('hex').substring(0, 16)}...`);
  });

  console.log('\n====================================================');
  console.log('  INVESTIGATIVE LEAD ATTRIBUTION (AGGREGATED)');
  console.log('====================================================');
  console.log(`  Target Handle:                ${result.candidate.actorProfile.primaryHandle}`);
  console.log(`  Investigative Score:          ${result.candidate.investigativeCorrelationScore} / 100 (Non-Saturated Unique Factor Sum)`);
  console.log(`  Execution Plane:              ${result.candidate.executionPlane}`);
  console.log(`  Ground-Truth Match:           ${result.candidate.groundTruthMatch ? 'CONTROLLED_LAB_PLANE: VERIFIED_MATCH' : 'MISMATCH'}`);
  console.log(`  Unique Factor Count:          ${result.candidate.aggregatedFactors.length}`);
  console.log('\n  Aggregated Relationship Factors:');
  result.candidate.aggregatedFactors.forEach((factor) => {
    console.log(`    - ${factor.category} (+${factor.weight}): ${factor.rationale}`);
    console.log(`      Supporting Observations:  ${factor.supportingEvidenceIds.length} evidence records`);
  });

  console.log('\n====================================================');
  console.log('  AUDITABLE AI SENTINEL REPORT');
  console.log('====================================================');
  console.log(`  Summary:              ${result.sentinelReport.summaryText}`);
  console.log(`  Advisory Rating:      ${result.sentinelReport.advisoryRating}`);
  console.log(`  Decision Authority:   ${result.sentinelReport.decisionAuthority}`);
  console.log(`  Cited Evidence IDs:   ${result.sentinelReport.citedEvidenceIds.join(', ')}`);

  console.log('\n====================================================');
  console.log('  STIX 2.1 JSON THREAT ACTOR BUNDLE EXPORTED');
  console.log('====================================================');
  console.log(JSON.stringify(result.stixBundle, null, 2));

  console.log('\n====================================================\n');
}

runE2EInvestigationDemo();
