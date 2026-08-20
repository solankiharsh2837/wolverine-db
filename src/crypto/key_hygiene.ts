import { WolverineError, WolverineErrorCode } from '../errors/index.js';

export const KNOWN_INSECURE_PLACEHOLDER_KEYS: string[] = [
  '0x0000000000000000000000000000000000000000000000000000000000000001',
  '0x0000000000000000000000000000000000000000000000000000000000000002',
  '0x0000000000000000000000000000000000000000000000000000000000000003',
  '0x0000000000000000000000000000000000000000000000000000000000000004',
  '0x0000000000000000000000000000000000000000000000000000000000000005',
];

/**
 * Asserts that a given private key or signing key is not a known insecure repository placeholder.
 * Throws in production environments.
 */
export function assertProductionKeyHygiene(keyHex: string): void {
  const isProduction = process.env.NODE_ENV === 'production';
  const cleanKey = keyHex.toLowerCase();

  const isKnownPlaceholder = KNOWN_INSECURE_PLACEHOLDER_KEYS.some(
    (k) => k.toLowerCase() === cleanKey || k.slice(2).toLowerCase() === cleanKey
  );

  if (isKnownPlaceholder) {
    if (isProduction) {
      throw new WolverineError(
        WolverineErrorCode.UNAUTHORIZED_MUTATION,
        '[SECURITY VIOLATION] Known insecure development private key rejected in production mode.'
      );
    }
  }
}
