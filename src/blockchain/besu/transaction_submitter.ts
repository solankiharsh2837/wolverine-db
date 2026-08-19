import { BesuClient } from './client.js';
import { BesuStateCommitmentInput, BesuCommitmentResult } from './types.js';
import { WolverineError, WolverineErrorCode } from '../../errors/index.js';

export class BesuTransactionSubmitter {
  constructor(private readonly client: BesuClient) {}

  public async submitStateCommitment(
    input: BesuStateCommitmentInput
  ): Promise<BesuCommitmentResult> {
    if (!input.customerSignatureHex || input.customerSignatureHex === '') {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        'Missing required customer authorization signature for blockchain submission'
      );
    }

    if (!input.agentSignatureHex || input.agentSignatureHex === '') {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        'Missing required agent attestation signature for blockchain submission'
      );
    }

    return this.client.submitCommitment(input);
  }
}
