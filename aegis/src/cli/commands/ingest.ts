import { EvidenceManager, EvidenceRecord } from '../../evidence/index.js';
import { EntityExtractor, ExtractedEntity } from '../../extraction/index.js';

export interface IngestResult {
  evidence: EvidenceRecord;
  extractedEntities: ExtractedEntity[];
}

export function handleIngest(
  sourceTypeStr: string,
  sourceUri: string,
  rawPayload: string
): IngestResult {
  const typeMap: Record<string, EvidenceRecord['sourceType']> = {
    osint: 'OSINT',
    darkweb: 'DARKWEB',
    telemetry: 'TELEMETRY',
    synthetic: 'LAB_SYNTHETIC',
  };

  const sourceType = typeMap[sourceTypeStr.toLowerCase()] || 'OSINT';
  const evidence = EvidenceManager.createEvidenceRecord(sourceType, sourceUri, rawPayload);
  const extractedEntities = EntityExtractor.extractEntities(evidence);

  return { evidence, extractedEntities };
}
