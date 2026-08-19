export interface ModelCheckerParams {
  totalValidators: number; // N
  quorumThreshold: number; // M
  maxByzantineFaults: number; // f
}

export interface ModelCheckerResult {
  exploredConfigurations: number;
  conflictingFinalityCounterexamples: number;
  safetyInvariantHolds: boolean;
  proofSummary: string;
}

export class ProtocolModelChecker {
  /**
   * Exhaustively verifies the non-equivocation / Byzantine safety theorem.
   */
  public static verifySafetyTheorem(
    params: ModelCheckerParams = { totalValidators: 5, quorumThreshold: 4, maxByzantineFaults: 1 }
  ): ModelCheckerResult {
    const { totalValidators: N, quorumThreshold: M, maxByzantineFaults: f } = params;

    let explored = 0;
    let counterexamples = 0;

    // A state configuration assigns each validator v in 0..N-1 a signing behavior for sequence S:
    // 0: Signs nothing
    // 1: Signs Proposal A only (honest)
    // 2: Signs Proposal B only (honest)
    // 3: Equivocates (signs both A and B) -> (only Byzantine nodes can do this)

    const totalPossibilities = Math.pow(4, N);

    for (let config = 0; config < totalPossibilities; config++) {
      let temp = config;
      let countA = 0;
      let countB = 0;
      let byzantineCount = 0;

      for (let v = 0; v < N; v++) {
        const behavior = temp % 4;
        temp = Math.floor(temp / 4);

        if (behavior === 1) {
          countA++;
        } else if (behavior === 2) {
          countB++;
        } else if (behavior === 3) {
          countA++;
          countB++;
          byzantineCount++;
        }
      }

      explored++;

      // Prune configurations that exceed the allowed Byzantine fault bound f
      if (byzantineCount <= f) {
        const finalizedA = countA >= M;
        const finalizedB = countB >= M;

        if (finalizedA && finalizedB) {
          // Counterexample found: Both A and B achieved Quorum for the same sequence!
          counterexamples++;
        }
      }
    }

    const safetyHolds = counterexamples === 0;

    return {
      exploredConfigurations: explored,
      conflictingFinalityCounterexamples: counterexamples,
      safetyInvariantHolds: safetyHolds,
      proofSummary: safetyHolds
        ? `FORMAL VERIFICATION PASSED: Explored ${explored} state configurations for N=${N}, M=${M}, f=${f}. Counterexamples = 0. Quorum intersection theorem guarantees P(conflicting finality) = 0.`
        : `SAFETY VIOLATION: Found ${counterexamples} counterexamples where conflicting proposals both achieved quorum!`,
    };
  }
}
