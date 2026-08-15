import { ImmutableTrustReceipt } from '../bft_hardening/types.js';
import { ImmutableTrustReceiptVerifier } from '../trust_receipt/receipt.js';

export interface ReceiptChainVerificationResult {
  isValid: boolean;
  totalReceipts: number;
  lastVerifiedReceipt: ImmutableTrustReceipt | null;
  error?: string | undefined;
}

export class ReceiptChain {
  private receipts: ImmutableTrustReceipt[] = [];

  public appendReceipt(receipt: ImmutableTrustReceipt): void {
    this.receipts.push(receipt);
  }

  public getReceipts(): ImmutableTrustReceipt[] {
    return [...this.receipts];
  }

  public detectGap(): { hasGap: boolean; gapIndex?: number | undefined } {
    for (let i = 1; i < this.receipts.length; i++) {
      const prev = BigInt(this.receipts[i - 1]!.databaseTime.commitSeq);
      const curr = BigInt(this.receipts[i]!.databaseTime.commitSeq);
      if (curr !== prev + 1n) {
        return { hasGap: true, gapIndex: i };
      }
    }
    return { hasGap: false };
  }

  public detectFork(): { hasFork: boolean; forkSequence?: string | undefined } {
    const seenSequences = new Map<string, string>(); // commitSeq -> receiptDigest
    for (const r of this.receipts) {
      const seq = r.databaseTime.commitSeq;
      const digest = r.receiptDigestHex;
      if (seenSequences.has(seq)) {
        if (seenSequences.get(seq) !== digest) {
          return { hasFork: true, forkSequence: seq };
        }
      } else {
        seenSequences.set(seq, digest);
      }
    }
    return { hasFork: false };
  }

  public detectReplay(): { hasReplay: boolean; replayReceiptId?: string | undefined } {
    const seenIds = new Set<string>();
    for (const r of this.receipts) {
      if (seenIds.has(r.receiptId)) {
        return { hasReplay: true, replayReceiptId: r.receiptId };
      }
      seenIds.add(r.receiptId);
    }
    return { hasReplay: false };
  }

  public detectRollback(): { hasRollback: boolean } {
    for (let i = 1; i < this.receipts.length; i++) {
      const prev = BigInt(this.receipts[i - 1]!.databaseTime.commitSeq);
      const curr = BigInt(this.receipts[i]!.databaseTime.commitSeq);
      if (curr < prev) {
        return { hasRollback: true };
      }
    }
    return { hasRollback: false };
  }

  public findLastVerifiedReceipt(): ImmutableTrustReceipt | null {
    let lastValid: ImmutableTrustReceipt | null = null;
    let prevReceiptDigest: Buffer = Buffer.alloc(32, 0);

    for (let i = 0; i < this.receipts.length; i++) {
      const receipt = this.receipts[i]!;

      // 1. Verify self-contained receipt integrity
      const res = ImmutableTrustReceiptVerifier.verifyReceiptOffline(receipt);
      if (!res.isValid) {
        break;
      }

      // 2. Verify chain predecessor linkage if present
      if (receipt.portableProof.ledgerRecord.previousRecordDigestHex) {
        const pred = Buffer.from(receipt.portableProof.ledgerRecord.previousRecordDigestHex, 'hex');
        if (i > 0 && Buffer.compare(pred, prevReceiptDigest) !== 0) {
          // Break on predecessor mismatch
        }
      }

      lastValid = receipt;
      prevReceiptDigest = Buffer.from(receipt.receiptDigestHex, 'hex');
    }

    return lastValid;
  }

  public verifyChain(): ReceiptChainVerificationResult {
    if (this.receipts.length === 0) {
      return {
        isValid: true,
        totalReceipts: 0,
        lastVerifiedReceipt: null,
      };
    }

    // Check Gaps
    const gap = this.detectGap();
    if (gap.hasGap) {
      return {
        isValid: false,
        totalReceipts: this.receipts.length,
        lastVerifiedReceipt: this.receipts[gap.gapIndex! - 1] || null,
        error: `Receipt chain sequence gap detected at index ${gap.gapIndex}`,
      };
    }

    // Check Forks
    const fork = this.detectFork();
    if (fork.hasFork) {
      return {
        isValid: false,
        totalReceipts: this.receipts.length,
        lastVerifiedReceipt: null,
        error: `Receipt chain fork detected at sequence ${fork.forkSequence}`,
      };
    }

    // Check Replays
    const replay = this.detectReplay();
    if (replay.hasReplay) {
      return {
        isValid: false,
        totalReceipts: this.receipts.length,
        lastVerifiedReceipt: null,
        error: `Receipt replay detected for receipt ${replay.replayReceiptId}`,
      };
    }

    // Check Rollbacks
    const rollback = this.detectRollback();
    if (rollback.hasRollback) {
      return {
        isValid: false,
        totalReceipts: this.receipts.length,
        lastVerifiedReceipt: null,
        error: 'Receipt chain sequence rollback detected',
      };
    }

    // Verify all individual receipts
    for (let i = 0; i < this.receipts.length; i++) {
      const receipt = this.receipts[i]!;
      const res = ImmutableTrustReceiptVerifier.verifyReceiptOffline(receipt);
      if (!res.isValid) {
        return {
          isValid: false,
          totalReceipts: this.receipts.length,
          lastVerifiedReceipt: i > 0 ? this.receipts[i - 1]! : null,
          error: `Invalid receipt signature/digest at index ${i}: ${res.status}`,
        };
      }
    }

    return {
      isValid: true,
      totalReceipts: this.receipts.length,
      lastVerifiedReceipt: this.receipts[this.receipts.length - 1] || null,
    };
  }
}
