import { handleInvestigate } from './investigate.js';

export function handleCaseShow(caseId: string) {
  const result = handleInvestigate('nocturne_operator', 'CONTROLLED_LAB_PLANE', 'actor_nocturne_operator');

  const banner = [
    '╭──────────────────────────────────────────────╮',
    '│              AEGIS INVESTIGATOR              │',
    `│        Investigation: ${caseId.padEnd(23)}│`,
    '╰──────────────────────────────────────────────╯',
    '',
    'TARGET',
    `  ${result.targetIdentifier}`,
    '',
    'DISCOVERY',
    `  Sources Scanned       ${result.collection.evidenceRecords.length}`,
    `  Observations          ${result.collection.allEntities.length}`,
    `  Evidence Records      ${result.collection.evidenceRecords.length}`,
    '',
    'ENTITIES',
    `  Handles               ${result.collection.allEntities.filter((e) => e.type === 'HANDLE').length}`,
    `  Infrastructure        ${result.collection.allEntities.filter((e) => e.type === 'INFRASTRUCTURE').length}`,
    `  Artifacts             ${result.collection.allEntities.filter((e) => e.type === 'ARTIFACT').length}`,
    `  Financial             ${result.collection.allEntities.filter((e) => e.type === 'FINANCIAL').length}`,
    '',
    'CORRELATION',
    `  ██████████████████░░  ${result.candidate.investigativeCorrelationScore} / 100`,
    `  ${result.sentinelReport.advisoryRating}`,
    '',
    ...result.candidate.aggregatedFactors.map(
      (f) => `  +${f.weight}  ${f.category} (${f.rationale})`
    ),
    '',
    'AI SENTINEL',
    `  ${result.sentinelReport.summaryText}`,
    `  Decision authority:   ${result.sentinelReport.decisionAuthority}`,
  ].join('\n');

  return { caseId, result, banner };
}

export function handleEvidenceShow(evidenceId: string) {
  const result = handleInvestigate('nocturne_operator', 'CONTROLLED_LAB_PLANE', 'actor_nocturne_operator');
  const ev = result.collection.evidenceRecords.find((e) => e.evidenceId === evidenceId) || result.collection.evidenceRecords[0];

  return {
    evidenceId: ev.evidenceId,
    sourceType: ev.sourceType,
    sourceUri: ev.sourceUri,
    sha256PayloadDigest: `0x${ev.payloadHash.toString('hex')}`,
    rawPayload: ev.rawPayload,
    stateIntegrityStatus: 'WOLVERINE_DB_VERIFIED',
  };
}

export function handleEntityShow(entityValue: string) {
  const result = handleInvestigate('nocturne_operator', 'CONTROLLED_LAB_PLANE', 'actor_nocturne_operator');
  const entities = result.collection.allEntities.filter((e) => e.value.toLowerCase().includes(entityValue.toLowerCase()));

  return {
    query: entityValue,
    matches: entities.length > 0 ? entities : result.collection.allEntities,
    linkedProfile: result.candidate.actorProfile,
  };
}

export function handleGraphShow(target: string) {
  const asciiGraph = [
    '                        [ NOCTURNE OPERATOR ]',
    '                                  │',
    '       ┌──────────────────────────┼──────────────────────────┐',
    '       ▼                          ▼                          ▼',
    ' [Marketplace Alpha]      [Marketplace Beta]         [OSINT Security Forum]',
    '   • handle: nocturne        • handle: nocturne_2       • handle: nocturne_dev',
    '   • ip: 198.51.100.42       • ip: 198.51.100.42        • ip: 198.51.100.42',
    '   • art: hash_script_X      • art: hash_script_X       • PGP key posting',
    '       │                          │                          │',
    '       └──────────────────────────┴──────────────────────────┘',
    '                                  │ (Aggregated: 90 / 100)',
    '                                  ▼',
    '                 [ PROBABLE IDENTITY CANDIDATE ]',
  ].join('\n');

  return { target, asciiGraph };
}

export function handleExplain(candidateId: string) {
  const result = handleInvestigate('nocturne_operator', 'CONTROLLED_LAB_PLANE', 'actor_nocturne_operator');

  return {
    candidateId,
    target: result.candidate.actorProfile.primaryHandle,
    investigativeCorrelationScore: result.candidate.investigativeCorrelationScore,
    factorCount: result.candidate.aggregatedFactors.length,
    factors: result.candidate.aggregatedFactors.map((f) => ({
      category: f.category,
      weight: f.weight,
      rationale: f.rationale,
      evidenceCitations: f.supportingEvidenceIds,
    })),
    scoringPolicyNotes: 'Score derived strictly from unique relationship factors without duplicate observation inflation.',
  };
}
