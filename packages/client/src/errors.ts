export type WolinErrorCode =
  | 'AUTH_ERROR'
  | 'PARSE_ERROR'
  | 'HTTP_ERROR'
  | 'PRECONDITION_FAILED'
  | 'INVALID_ARGUMENT';

export class WolinError extends Error {
  public readonly code: WolinErrorCode;

  constructor(code: WolinErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'WolinError';
    this.code = code;
  }
}

export class WolinAuthError extends WolinError {
  constructor(message: string, options?: ErrorOptions) {
    super('AUTH_ERROR', message, options);
    this.name = 'WolinAuthError';
  }
}

export class WolinParseError extends WolinError {
  constructor(message: string, options?: ErrorOptions) {
    super('PARSE_ERROR', message, options);
    this.name = 'WolinParseError';
  }
}

export interface WolinHttpErrorInit {
  status: number;
  statusText: string;
  url: string;
  method: string;
  body?: string;
  headers?: Headers;
  code?: WolinErrorCode;
  message?: string;
}

export class WolinHttpError extends WolinError {
  public readonly status: number;
  public readonly statusText: string;
  public readonly url: string;
  public readonly method: string;
  public readonly body: string;
  public readonly headers: Headers;

  constructor(init: WolinHttpErrorInit) {
    const defaultMsg = `HTTP ${init.status} ${init.statusText} (${init.method} ${init.url})${
      init.body ? `: ${init.body.slice(0, 256)}` : ''
    }`;
    super(init.code ?? 'HTTP_ERROR', init.message ?? defaultMsg);
    this.name = 'WolinHttpError';
    this.status = init.status;
    this.statusText = init.statusText;
    this.url = init.url;
    this.method = init.method;
    this.body = init.body ?? '';
    this.headers = init.headers ?? new Headers();
  }
}

export class WolinPreconditionError extends WolinHttpError {
  constructor(init: Omit<WolinHttpErrorInit, 'code'>) {
    super({
      ...init,
      code: 'PRECONDITION_FAILED',
    });
    this.name = 'WolinPreconditionError';
  }
}
