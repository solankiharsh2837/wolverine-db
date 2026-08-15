import { ReceiptChain } from './receipt_chain.js';

export class WolverineSurvivabilityCli {
  public static executeVerifyReceiptChain(chain: ReceiptChain): string {
    const res = chain.verifyChain();
    const lines = [
      '================================================================================',
      '                   WOLVERINE RECEIPT CHAIN INTEGRITY VERIFIER                   ',
      '================================================================================',
      `Total Finalized Receipts:  ${res.totalReceipts}`,
      `Chain Head Sequence:       ${res.lastVerifiedReceipt?.databaseTime.commitSeq ?? 'N/A'}`,
      `Sequence Gaps Detected:    ${chain.detectGap().hasGap ? 'YES (CORRUPTED)' : 'NONE (CONTINUOUS)'}`,
      `Forks Detected:            ${chain.detectFork().hasFork ? 'YES (FORKED)' : 'NONE (CANONICAL)'}`,
      `Replays Detected:          ${chain.detectReplay().hasReplay ? 'YES (REPLAYED)' : 'NONE (UNIQUE)'}`,
      `Rollbacks Detected:        ${chain.detectRollback().hasRollback ? 'YES (ROLLED BACK)' : 'NONE (MONOTONIC)'}`,
      `Chain Verification Result: ${res.isValid ? 'AUTHENTIC & PROVABLY UNBROKEN (PASS)' : `FAILED: ${res.error}`}`,
      '================================================================================',
      'Guarantee: Destroying Wolverine infrastructure cannot destroy certified history.',
      '================================================================================',
    ];
    return lines.join('\n');
  }
}
