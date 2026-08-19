import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export interface ConsumedNonceRecord {
  nonce: string; // Canonical UUID format (8-4-4-4-12)
  incidentId: string;
  approverPubkey: Buffer;
  consumedAt?: Date;
}

export interface IApprovalNonceStore {
  /**
   * Checks whether a given approval nonce has already been consumed.
   */
  isConsumed(nonce: Buffer | string): Promise<boolean> | boolean;

  /**
   * Records a consumed approval nonce.
   * Throws REPLAYED_APPROVAL_NONCE if the nonce is already recorded.
   */
  recordConsumed(
    nonce: Buffer | string,
    incidentId: string,
    approverPubkey: Buffer
  ): Promise<void> | void;
}

/**
 * Converts a 16-byte Buffer, 32-char hex string, or UUID string into canonical 8-4-4-4-12 UUID format.
 */
export function formatNonceUuid(nonce: Buffer | string): string {
  if (Buffer.isBuffer(nonce)) {
    if (nonce.length === 16) {
      const hex = nonce.toString('hex').toLowerCase();
      return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
    }
    const hex = nonce.toString('hex').toLowerCase().replace(/-/g, '');
    if (hex.length === 32) {
      return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
    }
    return hex;
  }

  const clean = nonce.toLowerCase().trim();
  if (clean.length === 36 && clean.includes('-')) {
    return clean;
  }
  const hex = clean.replace(/-/g, '');
  if (hex.length === 32) {
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  }
  return clean;
}

/**
 * In-memory implementation of IApprovalNonceStore for testing or standalone memory execution.
 */
export class InMemoryNonceStore implements IApprovalNonceStore {
  private readonly consumed = new Map<string, ConsumedNonceRecord>();

  constructor(initialNonces?: Iterable<string>) {
    if (initialNonces) {
      for (const n of initialNonces) {
        const canonical = formatNonceUuid(n);
        this.consumed.set(canonical, {
          nonce: canonical,
          incidentId: '00000000-0000-0000-0000-000000000000',
          approverPubkey: Buffer.alloc(32, 0),
          consumedAt: new Date(),
        });
      }
    }
  }

  public isConsumed(nonce: Buffer | string): boolean {
    const canonical = formatNonceUuid(nonce);
    return this.consumed.has(canonical);
  }

  public recordConsumed(
    nonce: Buffer | string,
    incidentId: string,
    approverPubkey: Buffer
  ): void {
    const canonical = formatNonceUuid(nonce);
    if (this.consumed.has(canonical)) {
      throw new WolverineError(
        WolverineErrorCode.REPLAYED_APPROVAL_NONCE,
        `Approval nonce ${canonical} has already been consumed`
      );
    }
    this.consumed.set(canonical, {
      nonce: canonical,
      incidentId: formatNonceUuid(incidentId),
      approverPubkey,
      consumedAt: new Date(),
    });
  }

  public getConsumedCount(): number {
    return this.consumed.size;
  }

  public clear(): void {
    this.consumed.clear();
  }
}
