import { WolverineError, WolverineErrorCode } from '../errors/index.js';

const STRICT_DECIMAL_REGEX = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?$/;

/**
 * Validates and normalizes a decimal string according to WolverineDB v0.1 grammar.
 * Rejects exponents, leading zeros, and negative zero ("-0", "-0.0").
 */
export function validateAndNormalizeDecimal(val: string): string {
  if (typeof val !== 'string') {
    throw new WolverineError(
      WolverineErrorCode.INVALID_DECIMAL_FORMAT,
      `Decimal value must be a string, got ${typeof val}`
    );
  }

  if (!STRICT_DECIMAL_REGEX.test(val)) {
    throw new WolverineError(
      WolverineErrorCode.INVALID_DECIMAL_FORMAT,
      `Decimal string "${val}" does not match strict grammar ^-?(0|[1-9][0-9]*)(\\.[0-9]+)?$`
    );
  }

  // Reject negative zero (-0, -0.0, -0.00, etc.)
  if (val.startsWith('-')) {
    const numPart = val.substring(1);
    const floatVal = parseFloat(numPart);
    if (floatVal === 0) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_DECIMAL_FORMAT,
        `Negative zero decimal "${val}" is forbidden`
      );
    }
  }

  let normalized = val;
  if (normalized.includes('.')) {
    normalized = normalized.replace(/(\.[0-9]*[1-9])0+$/, '$1').replace(/\.0+$/, '');
  }

  return normalized;
}

export function decimalToBuffer(val: string): Buffer {
  const normalized = validateAndNormalizeDecimal(val);
  return Buffer.from(normalized, 'ascii');
}
