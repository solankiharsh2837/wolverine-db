import { EvidenceRecord } from '../evidence/index.js';

export interface ExtractedEntity {
  entityId: string;
  type: 'HANDLE' | 'INFRASTRUCTURE' | 'ARTIFACT' | 'FINANCIAL' | 'STYLOMETRY';
  value: string;
  evidenceId: string;
}

export interface ActorCandidateProfile {
  actorId: string;
  primaryHandle: string;
  aliases: string[];
  entityNodeIds: string[];
}

export class EntityExtractor {
  public static extractEntities(evidence: EvidenceRecord): ExtractedEntity[] {
    const entities: ExtractedEntity[] = [];

    try {
      const parsed = JSON.parse(evidence.rawPayload);
      if (parsed.handle) {
        entities.push({
          entityId: `entity_handle_${parsed.handle}`,
          type: 'HANDLE',
          value: parsed.handle,
          evidenceId: evidence.evidenceId,
        });
      }
      if (parsed.ip) {
        entities.push({
          entityId: `entity_infra_${parsed.ip}`,
          type: 'INFRASTRUCTURE',
          value: parsed.ip,
          evidenceId: evidence.evidenceId,
        });
      }
      if (parsed.wallet) {
        entities.push({
          entityId: `entity_fin_${parsed.wallet}`,
          type: 'FINANCIAL',
          value: parsed.wallet,
          evidenceId: evidence.evidenceId,
        });
      }
      if (parsed.artifactHash) {
        entities.push({
          entityId: `entity_art_${parsed.artifactHash}`,
          type: 'ARTIFACT',
          value: parsed.artifactHash,
          evidenceId: evidence.evidenceId,
        });
      }
    } catch {
      // Non-JSON plain text fallback regex extraction
    }

    return entities;
  }
}
