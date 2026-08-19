import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { lstatSync, readFileSync } from 'node:fs';
import process from 'node:process';

const COOKIE_NAMES = ['CloudFront-Key-Pair-Id', 'CloudFront-Policy', 'CloudFront-Signature'];
const exactKeys = (value, expected) =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).toSorted().join('\0') === expected.toSorted().join('\0');

const fail = () => {
  throw new Error('E7_CLOUDFRONT_SIGNED_COOKIE_INVALID');
};

const canonicalUtc = (value) => {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    return false;
  }
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
};

const decode = (source, alphabet = 'base64') => {
  if (
    typeof source !== 'string' ||
    source.length < 2 ||
    source.length > 16_384 ||
    !(alphabet === 'cloudfront'
      ? /^[A-Za-z0-9_~-]+$/u.test(source)
      : /^[A-Za-z0-9+/]+={0,2}$/u.test(source))
  ) {
    fail();
  }
  const normalized =
    alphabet === 'cloudfront'
      ? source.replaceAll('-', '+').replaceAll('_', '=').replaceAll('~', '/')
      : source;
  try {
    return Buffer.from(normalized, 'base64').toString('utf8');
  } catch {
    fail();
  }
};

export const readCloudFrontSignedCookies = ({
  origin,
  source,
  now = new Date(),
  expectedState = 'VALID',
  expectedPublicKeyId,
  maxExpiresAtUtc,
}) => {
  if (source === undefined) return [];
  let cookies;
  let policy;
  try {
    cookies = JSON.parse(decode(source));
    policy = JSON.parse(decode(cookies?.['CloudFront-Policy'], 'cloudfront'));
  } catch {
    fail();
  }
  const statement = policy?.Statement?.[0];
  const expires = statement?.Condition?.DateLessThan?.['AWS:EpochTime'];
  const maximumExpiry =
    maxExpiresAtUtc === undefined || !canonicalUtc(maxExpiresAtUtc)
      ? undefined
      : Math.floor(Date.parse(maxExpiresAtUtc) / 1000);
  if (
    !exactKeys(cookies, COOKIE_NAMES) ||
    !/^[A-Z0-9]{8,64}$/u.test(cookies['CloudFront-Key-Pair-Id'] ?? '') ||
    (expectedPublicKeyId !== undefined &&
      (!/^[A-Z0-9]{8,64}$/u.test(expectedPublicKeyId) ||
        cookies['CloudFront-Key-Pair-Id'] !== expectedPublicKeyId)) ||
    !/^[A-Za-z0-9_~-]{16,8192}$/u.test(cookies['CloudFront-Signature'] ?? '') ||
    !exactKeys(policy, ['Statement']) ||
    !Array.isArray(policy.Statement) ||
    policy.Statement.length !== 1 ||
    !exactKeys(statement, ['Resource', 'Condition']) ||
    statement.Resource !== `${origin}/*` ||
    !exactKeys(statement.Condition, ['DateLessThan']) ||
    !exactKeys(statement.Condition.DateLessThan, ['AWS:EpochTime']) ||
    !Number.isSafeInteger(expires) ||
    (maxExpiresAtUtc !== undefined && maximumExpiry === undefined) ||
    !['VALID', 'EXPIRED'].includes(expectedState) ||
    (expectedState === 'VALID' && expires <= Math.floor(now.getTime() / 1000)) ||
    (expectedState === 'VALID' && maximumExpiry !== undefined && expires > maximumExpiry) ||
    (expectedState === 'EXPIRED' && expires > Math.floor(now.getTime() / 1000))
  ) {
    fail();
  }
  return COOKIE_NAMES.map((name) => ({
    name,
    value: cookies[name],
    url: origin,
    secure: true,
    httpOnly: true,
    sameSite: 'None',
    expires,
  }));
};

export const readCloudFrontSignedCookieFile = ({ filename, ...options }) => {
  if (filename === undefined) return [];
  let stat;
  try {
    stat = lstatSync(filename);
  } catch {
    fail();
  }
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.size < 2 ||
    stat.size > 24 * 1024 ||
    (process.platform !== 'win32' && (stat.mode & 0o077) !== 0)
  ) {
    fail();
  }
  const source = readFileSync(filename, 'utf8');
  if (source !== source.trim()) fail();
  return readCloudFrontSignedCookies({ ...options, source });
};

export const assertCloudFrontAccessMaterialExcluded = (value, cookies) => {
  const serialized = JSON.stringify(value);
  if (cookies.some(({ value: cookieValue }) => serialized.includes(cookieValue))) {
    throw new Error('E7_CLOUDFRONT_ACCESS_MATERIAL_LEAK');
  }
  return value;
};

export const validatePrereleaseApiOrigin = ({ origin, region }) => {
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    throw new Error('E7_PRERELEASE_API_ORIGIN_INVALID');
  }
  const escapedRegion = String(region ?? '').replaceAll(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  if (
    !/^[a-z]{2}(?:-gov)?-[a-z]+-[1-9]$/u.test(region ?? '') ||
    parsed.protocol !== 'https:' ||
    parsed.origin !== origin ||
    parsed.pathname !== '/' ||
    parsed.username ||
    parsed.password ||
    parsed.port ||
    parsed.search ||
    parsed.hash ||
    !new RegExp(`^[a-z0-9]{10}\\.execute-api\\.${escapedRegion}\\.amazonaws\\.com$`, 'u').test(
      parsed.hostname,
    )
  ) {
    throw new Error('E7_PRERELEASE_API_ORIGIN_INVALID');
  }
  return parsed.origin;
};

const encodePolicy = (value) =>
  Buffer.from(JSON.stringify(value), 'utf8')
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('=', '_')
    .replaceAll('/', '~');

export const selfTestCloudFrontAccess = () => {
  const origin = 'https://d111111abcdef8.cloudfront.net';
  const policy = (expires) => ({
    Statement: [
      {
        Resource: `${origin}/*`,
        Condition: { DateLessThan: { 'AWS:EpochTime': expires } },
      },
    ],
  });
  const encoded = (overrides = {}) =>
    Buffer.from(
      JSON.stringify({
        'CloudFront-Key-Pair-Id': 'K2STAGE7CHECKOUT',
        'CloudFront-Policy': encodePolicy(policy(1_800_000_000)),
        'CloudFront-Signature': 'syntheticSignatureValue1234567890',
        ...overrides,
      }),
      'utf8',
    ).toString('base64');
  const validCookies = readCloudFrontSignedCookies({
    origin,
    source: encoded(),
    now: new Date('2026-08-17T12:00:00.000Z'),
    expectedPublicKeyId: 'K2STAGE7CHECKOUT',
    maxExpiresAtUtc: '2027-01-15T08:00:00.000Z',
  });
  assert.equal(validCookies.length, 3);
  assert.deepEqual(assertCloudFrontAccessMaterialExcluded({ status: 'PASS' }, validCookies), {
    status: 'PASS',
  });
  assert.throws(
    () => assertCloudFrontAccessMaterialExcluded({ leaked: validCookies[1].value }, validCookies),
    /E7_CLOUDFRONT_ACCESS_MATERIAL_LEAK/u,
  );
  assert.deepEqual(readCloudFrontSignedCookies({ origin, source: undefined }), []);
  assert.throws(() =>
    readCloudFrontSignedCookies({
      origin,
      source: encoded(),
      expectedPublicKeyId: 'K9DIFFERENTPUBLICKEY',
    }),
  );
  assert.throws(() =>
    readCloudFrontSignedCookies({
      origin,
      source: encoded(),
      now: new Date('2026-08-17T12:00:00.000Z'),
      expectedPublicKeyId: 'K2STAGE7CHECKOUT',
      maxExpiresAtUtc: '2026-08-17T13:00:00.000Z',
    }),
  );
  assert.throws(() =>
    readCloudFrontSignedCookies({
      origin,
      source: encoded({ 'CloudFront-Policy': encodePolicy(policy(1)) }),
      now: new Date('2026-08-17T12:00:00.000Z'),
    }),
  );
  assert.equal(
    readCloudFrontSignedCookies({
      origin,
      source: encoded({ 'CloudFront-Policy': encodePolicy(policy(1)) }),
      now: new Date('2026-08-17T12:00:00.000Z'),
      expectedState: 'EXPIRED',
    }).length,
    3,
  );
  assert.throws(() =>
    readCloudFrontSignedCookies({
      origin,
      source: encoded({
        'CloudFront-Policy': encodePolicy({ ...policy(1_800_000_000), extra: 1 }),
      }),
    }),
  );
  assert.equal(
    validatePrereleaseApiOrigin({
      origin: 'https://abc123def4.execute-api.us-east-1.amazonaws.com',
      region: 'us-east-1',
    }),
    'https://abc123def4.execute-api.us-east-1.amazonaws.com',
  );
  for (const invalidOrigin of [
    'http://abc123def4.execute-api.us-east-1.amazonaws.com',
    'https://abc123def4.execute-api.us-west-2.amazonaws.com',
    'https://abc123def4.execute-api.us-east-1.amazonaws.com/path',
    'https://execute-api.us-east-1.amazonaws.com',
  ]) {
    assert.throws(() =>
      validatePrereleaseApiOrigin({ origin: invalidOrigin, region: 'us-east-1' }),
    );
  }
};
