import { redactLogRecord, SafeLogger } from './safe-logger';

describe('safe logging', () => {
  it('redacts nested sensitive keys and arrays', () => {
    expect(
      redactLogRecord({
        authorization: 'value',
        nested: { cardToken: 'value' },
        values: [{ address: 'value' }],
      }),
    ).toEqual({
      authorization: '[REDACTED]',
      nested: { cardToken: '[REDACTED]' },
      values: [{ address: '[REDACTED]' }],
    });
  });

  it('writes one structured allowlisted line', () => {
    const write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    new SafeLogger('api', 'test', '1').info('test.event', { correlationId: 'correlation-01' });
    expect(write).toHaveBeenCalledTimes(1);
    expect(String(write.mock.calls[0]?.[0])).toContain('test.event');
  });
});
