const redacted = '[REDACTED]';
const sensitiveKey =
  /authorization|cookie|secret|token|password|pan|card|cvc|cvv|address|(?:api|private|root|hmac).*key/i;

export type SafeLogValue = string | number | boolean | null | SafeLogRecord | SafeLogValue[];
export interface SafeLogRecord {
  readonly [key: string]: SafeLogValue;
}

export const redactLogRecord = (record: SafeLogRecord): SafeLogRecord =>
  Object.entries(record).reduce<SafeLogRecord>((sanitized, [key, value]) => {
    if (sensitiveKey.test(key)) {
      return { ...sanitized, [key]: redacted };
    }
    if (Array.isArray(value)) {
      return {
        ...sanitized,
        [key]: value.map((item) =>
          typeof item === 'object' && item !== null ? redactLogRecord(item as SafeLogRecord) : item,
        ),
      };
    }
    if (typeof value === 'object' && value !== null) {
      return { ...sanitized, [key]: redactLogRecord(value) };
    }
    return { ...sanitized, [key]: value };
  }, {});

const allowedFields: Readonly<Record<string, (value: SafeLogValue) => boolean>> = {
  requestId: (value) => typeof value === 'string',
  correlationId: (value) => typeof value === 'string',
  route: (value) => typeof value === 'string' && value.startsWith('/api/'),
  method: (value) => typeof value === 'string' && /^(GET|POST|PUT|PATCH|DELETE)$/.test(value),
  durationMs: (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0,
  resultCode: (value) => typeof value === 'number' && Number.isInteger(value),
  fromState: (value) => typeof value === 'string' && /^[A-Z_]+$/.test(value),
  toState: (value) => typeof value === 'string' && /^[A-Z_]+$/.test(value),
  dispatchPhase: (value) => typeof value === 'string' && /^[A-Z_]+$/.test(value),
  providerStatus: (value) =>
    value === null || (typeof value === 'string' && /^[A-Z_]+$/.test(value)),
  errorCode: (value) => typeof value === 'string' && /^[A-Z0-9_]+$/.test(value),
  retryCount: (value) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0,
  metricName: (value) => typeof value === 'string' && /^[a-z][a-z0-9_]+$/.test(value),
  metricValue: (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0,
};

export const allowlistLogFields = (record: SafeLogRecord): SafeLogRecord =>
  Object.entries(record).reduce<SafeLogRecord>((allowed, [key, value]) => {
    const accepts = allowedFields[key];
    return accepts?.(value) === true ? { ...allowed, [key]: value } : allowed;
  }, {});

export class SafeLogger {
  public constructor(
    private readonly service: string,
    private readonly environment: string,
    private readonly version: string,
  ) {}

  public info(eventName: string, fields: SafeLogRecord): void {
    const entry = {
      timestamp: new Date().toISOString(),
      level: 'info',
      service: this.service,
      environment: this.environment,
      version: this.version,
      eventName,
      ...allowlistLogFields(fields),
    };
    process.stdout.write(`${JSON.stringify(entry)}\n`);
  }
}
