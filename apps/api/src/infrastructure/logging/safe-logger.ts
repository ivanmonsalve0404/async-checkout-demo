const redacted = '[REDACTED]';
const sensitiveKey = /authorization|cookie|secret|token|password|pan|card|cvc|cvv|address/i;

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

export class SafeLogger {
  public constructor(
    private readonly service: string,
    private readonly environment: string,
    private readonly version: string,
  ) {}

  public info(eventName: string, fields: SafeLogRecord): void {
    const entry = redactLogRecord({
      timestamp: new Date().toISOString(),
      level: 'info',
      service: this.service,
      environment: this.environment,
      version: this.version,
      eventName,
      ...fields,
    });
    process.stdout.write(`${JSON.stringify(entry)}\n`);
  }
}
