import { StixExporter, StixBundle } from '../../stix/index.js';
import { AttributionCandidate } from '../../attribution/index.js';

export function handleExportStix21(candidate: AttributionCandidate): StixBundle {
  return StixExporter.exportCandidateToStix21(candidate);
}
