import { DiscoveryEngine, RawDiscoveryObservation } from '../discovery/index.js';
import { EvidenceManager, EvidenceRecord } from '../evidence/index.js';
import { EntityExtractor, ExtractedEntity } from '../extraction/index.js';

export interface CollectionResult {
  evidenceRecords: EvidenceRecord[];
  allEntities: ExtractedEntity[];
}

export class CollectionEngine {
  public static collectAndNormalizeTarget(targetIdentifier: string): CollectionResult {
    const rawObs: RawDiscoveryObservation[] = DiscoveryEngine.discoverObservationsForTarget(targetIdentifier);

    const evidenceRecords: EvidenceRecord[] = [];
    const allEntities: ExtractedEntity[] = [];

    for (const obs of rawObs) {
      const evidence = EvidenceManager.createEvidenceRecord(obs.sourceType, obs.sourceUri, obs.payload);
      evidenceRecords.push(evidence);

      const extracted = EntityExtractor.extractEntities(evidence);
      allEntities.push(...extracted);
    }

    return { evidenceRecords, allEntities };
  }
}
