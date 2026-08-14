export interface CorrelationPolicy {
  artifactReuseWeight: number; // default +25
  infraColocationWeight: number; // default +20
  handleSimilarityWeight: number; // default +15
  stylometricMatchWeight: number; // default +12
  temporalCorrelationWeight: number; // default +10
  identityResolutionThreshold: number; // default 75
}

export const DEFAULT_CORRELATION_POLICY: CorrelationPolicy = {
  artifactReuseWeight: 25,
  infraColocationWeight: 20,
  handleSimilarityWeight: 15,
  stylometricMatchWeight: 12,
  temporalCorrelationWeight: 10,
  identityResolutionThreshold: 75,
};
