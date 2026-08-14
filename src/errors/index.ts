import { WolverineErrorCode } from './codes.js';

export class WolverineError extends Error {
  public readonly code: WolverineErrorCode;
  public readonly operation?: string;
  public readonly retryable: boolean;
  public readonly causeCategory?: string;

  constructor(
    code: WolverineErrorCode,
    message: string,
    options?: {
      operation?: string;
      retryable?: boolean;
      causeCategory?: string;
      cause?: Error;
    }
  ) {
    super(message);
    this.name = 'WolverineError';
    this.code = code;
    if (options?.operation !== undefined) {
      this.operation = options.operation;
    }
    this.retryable = options?.retryable ?? false;
    if (options?.causeCategory !== undefined) {
      this.causeCategory = options.causeCategory;
    }

    if (options?.cause) {
      this.cause = options.cause;
    }

    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export * from './codes.js';
