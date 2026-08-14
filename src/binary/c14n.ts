import { WolverineError, WolverineErrorCode } from '../errors/index.js';

/**
 * RFC 8785 Canonical JSON (JSON-C14N) Implementation
 * Sorts object keys based on UTF-16 code units, omits unescaped whitespace.
 */
export function canonicalizeJson(val: unknown): string {
  if (val === null) {
    return 'null';
  }

  if (typeof val === 'boolean') {
    return val ? 'true' : 'false';
  }

  if (typeof val === 'number') {
    if (!Number.isFinite(val)) {
      throw new WolverineError(
        WolverineErrorCode.INVALID_JSON_C14N,
        `Cannot canonicalize non-finite number: ${val}`
      );
    }
    return JSON.stringify(val);
  }

  if (typeof val === 'string') {
    return JSON.stringify(val);
  }

  if (Array.isArray(val)) {
    const items = val.map((item) => canonicalizeJson(item));
    return '[' + items.join(',') + ']';
  }

  if (typeof val === 'object') {
    const keys = Object.keys(val as Record<string, unknown>).sort((k1, k2) => {
      const len1 = k1.length;
      const len2 = k2.length;
      const minLen = Math.min(len1, len2);
      for (let i = 0; i < minLen; i++) {
        const c1 = k1.charCodeAt(i);
        const c2 = k2.charCodeAt(i);
        if (c1 !== c2) {
          return c1 - c2;
        }
      }
      return len1 - len2;
    });

    const entries = keys.map((key) => {
      const serializedKey = JSON.stringify(key);
      const serializedVal = canonicalizeJson(
        (val as Record<string, unknown>)[key]
      );
      return `${serializedKey}:${serializedVal}`;
    });

    return '{' + entries.join(',') + '}';
  }

  throw new WolverineError(
    WolverineErrorCode.INVALID_JSON_C14N,
    `Unsupported value type for JSON canonicalization: ${typeof val}`
  );
}

/**
 * Converts value to RFC 8785 Canonical JSON UTF-8 Buffer
 */
export function canonicalizeJsonToBuffer(val: unknown): Buffer {
  const jsonStr = canonicalizeJson(val);
  return Buffer.from(jsonStr, 'utf8');
}
