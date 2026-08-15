import { strict as assert } from 'node:assert';
import { describe, test } from 'node:test';

import { parseFoundationConfig } from '../lib/config';

void describe('foundation configuration', () => {
  void test('uses reversible fake-only defaults', () => {
    assert.deepEqual(parseFoundationConfig({}), {
      projectName: 'checkout',
      environment: 'preview',
      region: 'us-east-1',
      paymentAdapter: 'fake',
      paymentsEnabled: false,
      tokenizationMode: 'disabled',
    });
  });

  void test('rejects any real payment path', () => {
    assert.throws(() => parseFoundationConfig({ paymentAdapter: 'real' }), /fake payment adapter/);
    assert.throws(() => parseFoundationConfig({ paymentsEnabled: true }), /paymentsEnabled=false/);
    assert.throws(
      () => parseFoundationConfig({ tokenizationMode: 'direct' }),
      /tokenizationMode=disabled/,
    );
  });

  void test('rejects production, sandbox and malformed context', () => {
    assert.throws(() => parseFoundationConfig({ environment: 'sandbox' }), /fake-only preview/);
    assert.throws(() => parseFoundationConfig({ environment: 'production' }), /fake-only preview/);
    assert.throws(() => parseFoundationConfig({ region: 'not-a-region' }), /AWS region identifier/);
    assert.throws(() => parseFoundationConfig({ projectName: 'Checkout Demo' }), /lowercase/);
    assert.throws(
      () => parseFoundationConfig({ projectName: { unsafe: true } }),
      /must be a string/,
    );
  });
});
