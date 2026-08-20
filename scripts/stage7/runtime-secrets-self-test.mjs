import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { canonicalJson, workspaceRoot } from './core.mjs';
import {
  createStage7RuntimeSecretsInput,
  hydrateStage7RuntimeSecretsFile,
  initializeStage7RuntimeSecretsFile,
  isProviderAcceptanceTokenUsable,
  isWompiProviderPermalink,
  materializeStage7RuntimeSecrets,
  readWompiSandboxMerchant,
  Stage7RuntimeSecretsError,
  stage7RuntimeSecretTargets,
  validateStage7RuntimeSecretsFile,
  validateStage7RuntimeSecretsInput,
} from './runtime-secrets.mjs';

const ACCOUNT_ID = ['903479', '130598'].join('');
const NOW = new Date('2026-08-19T18:00:00.000Z');

const acceptanceJwt = (payload) =>
  [
    Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
    Buffer.from(JSON.stringify(payload)).toString('base64url'),
    Buffer.from('synthetic-signature').toString('base64url'),
  ].join('.');

const sandboxValues = () => ({
  publicKey: ['pub', 'test', 'synthetic-runtime-public'].join('_'),
  privateKey: ['prv', 'test', 'synthetic-runtime-private'].join('_'),
  integritySecret: ['test', 'integrity', 'synthetic-runtime-integrity'].join('_'),
  termsAcceptanceToken: 'terms-acceptance-synthetic',
  termsPermalink: 'https://comercios.wompi.co/terms/synthetic',
  personalDataAcceptanceToken: acceptanceJwt({ contract_id: 2 }),
  personalDataPermalink: 'https://wompi.com/personal-data/synthetic',
});

const sandboxCredentialsOnly = () => ({
  ...sandboxValues(),
  personalDataAcceptanceToken: null,
  personalDataPermalink: null,
  termsAcceptanceToken: null,
  termsPermalink: null,
});

const wompiPayload = () => {
  const sandbox = sandboxValues();
  return {
    data: {
      presigned_acceptance: {
        acceptance_token: sandbox.termsAcceptanceToken,
        permalink: sandbox.termsPermalink,
        type: 'END_USER_POLICY',
      },
      presigned_personal_data_auth: {
        acceptance_token: sandbox.personalDataAcceptanceToken,
        permalink: sandbox.personalDataPermalink,
        type: 'PERSONAL_DATA_AUTH',
      },
    },
  };
};

const wompiResponse = (url, { payload = wompiPayload(), ...overrides } = {}) => {
  return {
    body: Buffer.from(JSON.stringify(payload), 'utf8'),
    contentType: 'application/json; charset=utf-8',
    redirected: false,
    status: 200,
    url,
    ...overrides,
  };
};

const writeInput = (filename, value) =>
  writeFileSync(filename, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
const cloneJson = (value) => JSON.parse(JSON.stringify(value));

const argumentValue = (arguments_, name) => arguments_[arguments_.indexOf(name) + 1];

const fakeAws = ({ accountId = ACCOUNT_ID } = {}) => {
  const calls = [];
  const secrets = new Map();
  let versionCounter = 0;
  const response = (value) => ({ status: 0, stderr: '', stdout: JSON.stringify(value) });
  const executor = (arguments_) => {
    calls.push([...arguments_]);
    if (arguments_.includes('sts') && arguments_.includes('get-caller-identity')) {
      return response({
        Account: accountId,
        Arn: `arn:aws:iam::${accountId}:user/synthetic-operator`,
        UserId: 'SYNTHETICOPERATOR',
      });
    }
    const nameOrArn = argumentValue(arguments_, '--secret-id');
    const byIdentifier = () =>
      [...secrets.values()].find((secret) => secret.name === nameOrArn || secret.arn === nameOrArn);
    if (arguments_.includes('describe-secret')) {
      const secret = byIdentifier();
      if (secret === undefined) {
        return {
          status: 254,
          stdout: '',
          stderr: 'ResourceNotFoundException',
        };
      }
      return response({
        ARN: secret.arn,
        Name: secret.name,
        RotationEnabled: false,
        Tags: secret.tags,
      });
    }
    if (arguments_.includes('create-secret')) {
      const name = argumentValue(arguments_, '--name');
      if (secrets.has(name)) {
        return { status: 254, stdout: '', stderr: 'ResourceExistsException' };
      }
      const region = argumentValue(arguments_, '--region');
      const payloadReference = argumentValue(arguments_, '--secret-string');
      assert.match(payloadReference, /^file:\/\//u);
      const source = readFileSync(payloadReference.slice('file://'.length), 'utf8');
      versionCounter += 1;
      const versionId = `11111111-2222-4333-8444-${String(versionCounter).padStart(12, '0')}`;
      const tagStart = arguments_.indexOf('--tags') + 1;
      const tagEnd = arguments_.indexOf('--region');
      const tags = arguments_.slice(tagStart, tagEnd).map((entry) => {
        const match = /^Key=([^,]+),Value=(.+)$/u.exec(entry);
        assert.notEqual(match, null);
        return { Key: match[1], Value: match[2] };
      });
      const secret = {
        arn: `arn:aws:secretsmanager:${region}:${accountId}:secret:${name}-Ab1Cd2`,
        name,
        source,
        tags,
        versionId,
      };
      secrets.set(name, secret);
      return response({ ARN: secret.arn, Name: name, VersionId: versionId });
    }
    if (arguments_.includes('get-secret-value')) {
      const secret = byIdentifier();
      assert.notEqual(secret, undefined);
      return response({
        ARN: secret.arn,
        Name: secret.name,
        SecretString: secret.source,
        VersionId: secret.versionId,
        VersionStages: ['AWSCURRENT'],
      });
    }
    assert.fail(`Unexpected synthetic AWS operation: ${arguments_.join(' ')}`);
  };
  return { calls, executor, secrets };
};

let assertions = 0;
let canaries = 0;
const equal = (actual, expected) => {
  assertions += 1;
  assert.equal(actual, expected);
};
const ok = (value) => {
  assertions += 1;
  assert.ok(value);
};
const rejects = (callback, expectedCode) => {
  canaries += 1;
  assertions += 1;
  assert.throws(
    callback,
    (error) => error instanceof Stage7RuntimeSecretsError && error.code === expectedCode,
  );
};
const rejectsAsync = async (callback, expectedCode) => {
  canaries += 1;
  assertions += 1;
  await assert.rejects(
    callback,
    (error) => error instanceof Stage7RuntimeSecretsError && error.code === expectedCode,
  );
};

const selfTestParent = path.join(workspaceRoot, '.stage7', 'private');
mkdirSync(selfTestParent, { recursive: true, mode: 0o700 });
const selfTestRoot = mkdtempSync(path.join(selfTestParent, '.runtime-secrets-selftest-'));
try {
  if (process.platform === 'win32') {
    const foreignAcl = spawnSync('icacls.exe', [selfTestRoot, '/grant', '*S-1-1-0:(RX)'], {
      encoding: 'utf8',
      timeout: 10_000,
      windowsHide: true,
    });
    equal(foreignAcl.status, 0);
  }
  const inputFilename = path.join(selfTestRoot, 'stage7-runtime-secrets.json');
  const initialized = initializeStage7RuntimeSecretsFile({
    accountId: ACCOUNT_ID,
    inputFilename,
    privateRoot: selfTestRoot,
  });
  equal(initialized.status, 'INITIALIZED_PRIVATE_INPUT');
  const initializedInput = JSON.parse(readFileSync(inputFilename, 'utf8'));
  equal(initializedInput.sandbox.publicKey, null);
  for (const targetName of Object.keys(stage7RuntimeSecretTargets)) {
    ok(/^[A-Za-z0-9_-]{43}$/u.test(initializedInput.targets[targetName].runtimeSecurityRootKey));
    ok(/^[A-Za-z0-9_-]{43}$/u.test(initializedInput.targets[targetName].prereleaseOriginToken));
  }
  rejects(
    () =>
      initializeStage7RuntimeSecretsFile({
        accountId: ACCOUNT_ID,
        inputFilename,
        privateRoot: selfTestRoot,
      }),
    'E7_RUNTIME_SECRETS_INPUT_ALREADY_EXISTS',
  );

  initializedInput.sandbox = sandboxCredentialsOnly();
  delete initializedInput.targets.full.runtimeSecurityRootKey;
  writeInput(inputFilename, initializedInput);
  rejects(
    () => validateStage7RuntimeSecretsFile({ inputFilename, now: NOW, privateRoot: selfTestRoot }),
    'E7_RUNTIME_SECRETS_SANDBOX_INVALID',
  );

  const missingGeneratedInput = JSON.parse(readFileSync(inputFilename, 'utf8'));
  missingGeneratedInput.targets.full.runtimeSecurityRootKey = Buffer.alloc(32, 19).toString(
    'base64url',
  );
  writeInput(inputFilename, missingGeneratedInput);
  const merchantCalls = [];
  const merchantReader = async (url) => {
    merchantCalls.push(url);
    return Promise.resolve(wompiResponse(url));
  };
  const hydrated = await hydrateStage7RuntimeSecretsFile({
    inputFilename,
    merchantReader,
    now: NOW,
    privateRoot: selfTestRoot,
  });
  equal(hydrated.status, 'HYDRATED_PRIVATE_INPUT');
  equal(merchantCalls.length, 1);
  ok(merchantCalls[0].startsWith('https://sandbox.wompi.co/v1/merchants/'));
  const alreadyHydrated = await hydrateStage7RuntimeSecretsFile({
    inputFilename,
    merchantReader,
    now: NOW,
    privateRoot: selfTestRoot,
  });
  equal(alreadyHydrated.status, 'ALREADY_HYDRATED');
  equal(merchantCalls.length, 1);

  const hydratedInputWithMissingGenerated = JSON.parse(readFileSync(inputFilename, 'utf8'));
  delete hydratedInputWithMissingGenerated.targets.full.runtimeSecurityRootKey;
  writeInput(inputFilename, hydratedInputWithMissingGenerated);

  const aws = fakeAws();
  const first = materializeStage7RuntimeSecrets({
    executor: aws.executor,
    inputFilename,
    now: NOW,
    privateRoot: selfTestRoot,
    profile: 'assessment-bootstrap',
  });
  equal(first.status, 'MATERIALIZED_AND_VERIFIED');
  equal(first.targets.full.action, 'CREATED');
  equal(first.targets.prerelease.action, 'CREATED');
  equal(aws.secrets.size, 2);
  const completedInput = JSON.parse(readFileSync(inputFilename, 'utf8'));
  ok(/^[A-Za-z0-9_-]{43}$/u.test(completedInput.targets.full.runtimeSecurityRootKey));
  const localValidation = validateStage7RuntimeSecretsFile({
    inputFilename,
    now: NOW,
    privateRoot: selfTestRoot,
  });
  equal(localValidation.status, 'VALIDATED_LOCALLY');
  equal(localValidation.targets.full.secretDocumentSha256, first.targets.full.secretDocumentSha256);

  const second = materializeStage7RuntimeSecrets({
    executor: aws.executor,
    inputFilename,
    now: NOW,
    privateRoot: selfTestRoot,
    profile: 'assessment-bootstrap',
  });
  equal(second.targets.full.action, 'VERIFIED_EXISTING');
  equal(second.targets.prerelease.action, 'VERIFIED_EXISTING');
  equal(second.targets.full.versionId, first.targets.full.versionId);
  equal(second.targets.prerelease.versionId, first.targets.prerelease.versionId);

  const serializedResult = canonicalJson(second);
  for (const sensitiveValue of [
    ...Object.values(sandboxValues()),
    completedInput.targets.full.runtimeSecurityRootKey,
    completedInput.targets.full.prereleaseOriginToken,
  ]) {
    equal(serializedResult.includes(sensitiveValue), false);
    equal(
      aws.calls.some((arguments_) => arguments_.includes(sensitiveValue)),
      false,
    );
  }
  equal(serializedResult.includes('SecretString'), false);

  const changedInput = cloneJson(completedInput);
  changedInput.sandbox.publicKey = ['pub', 'test', 'different-synthetic-value'].join('_');
  writeInput(inputFilename, changedInput);
  rejects(
    () =>
      materializeStage7RuntimeSecrets({
        executor: aws.executor,
        inputFilename,
        now: NOW,
        privateRoot: selfTestRoot,
        profile: 'assessment-bootstrap',
      }),
    'E7_RUNTIME_SECRETS_EXISTING_VALUE_MISMATCH',
  );
  writeInput(inputFilename, completedInput);

  const mismatchedAws = fakeAws({ accountId: ['111111', '222222'].join('') });
  rejects(
    () =>
      materializeStage7RuntimeSecrets({
        executor: mismatchedAws.executor,
        inputFilename,
        now: NOW,
        privateRoot: selfTestRoot,
        profile: 'assessment-bootstrap',
      }),
    'E7_RUNTIME_SECRETS_AWS_ACCOUNT_MISMATCH',
  );
  equal(
    mismatchedAws.calls.some((arguments_) => arguments_.includes('create-secret')),
    false,
  );

  const hydrationDraft = cloneJson(completedInput);
  hydrationDraft.sandbox = sandboxCredentialsOnly();
  writeInput(inputFilename, hydrationDraft);
  await rejectsAsync(
    () =>
      hydrateStage7RuntimeSecretsFile({
        inputFilename,
        merchantReader: async (url) => Promise.resolve(wompiResponse(url, { redirected: true })),
        now: NOW,
        privateRoot: selfTestRoot,
      }),
    'E7_RUNTIME_SECRETS_WOMPI_RESPONSE_INVALID',
  );
  await rejectsAsync(
    () => readWompiSandboxMerchant('https://sandbox.wompi.co.example.test/v1/merchants/x'),
    'E7_RUNTIME_SECRETS_WOMPI_URL_INVALID',
  );
  const missingTypePayload = wompiPayload();
  delete missingTypePayload.data.presigned_acceptance.type;
  const wrongTypePayload = wompiPayload();
  wrongTypePayload.data.presigned_personal_data_auth.type = 'END_USER_POLICY';
  const extraKeyPayload = wompiPayload();
  extraKeyPayload.data.presigned_acceptance.unexpected = true;
  for (const payload of [missingTypePayload, wrongTypePayload, extraKeyPayload]) {
    await rejectsAsync(
      () =>
        hydrateStage7RuntimeSecretsFile({
          inputFilename,
          merchantReader: async (url) => Promise.resolve(wompiResponse(url, { payload })),
          now: NOW,
          privateRoot: selfTestRoot,
        }),
      'E7_RUNTIME_SECRETS_WOMPI_RESPONSE_INVALID',
    );
  }
  writeInput(inputFilename, completedInput);

  const currentEpochSeconds = NOW.getTime() / 1_000;
  equal(
    isProviderAcceptanceTokenUsable(acceptanceJwt({ exp: currentEpochSeconds + 901 }), {
      now: NOW,
      minimumRemainingSeconds: 900,
    }),
    true,
  );
  equal(
    isProviderAcceptanceTokenUsable(acceptanceJwt({ exp: currentEpochSeconds + 900 }), {
      now: NOW,
      minimumRemainingSeconds: 900,
    }),
    false,
  );
  equal(isProviderAcceptanceTokenUsable('synthetic.invalid-token.signature', { now: NOW }), false);
  equal(isWompiProviderPermalink('https://merchant.wompi.co/terms'), true);
  equal(isWompiProviderPermalink('https://wompi.com/personal-data'), true);
  equal(isWompiProviderPermalink('https://wompi.com.example.test/terms'), false);
  equal(isWompiProviderPermalink('https://evilwompi.co/terms'), false);

  const expiredInput = cloneJson(completedInput);
  expiredInput.sandbox.termsAcceptanceToken = acceptanceJwt({
    exp: currentEpochSeconds + 900,
  });
  rejects(
    () => validateStage7RuntimeSecretsInput(expiredInput, { now: NOW }),
    'E7_RUNTIME_SECRETS_SANDBOX_INVALID',
  );

  const extendedInput = cloneJson(completedInput);
  extendedInput.targets.full.unexpected = true;
  rejects(
    () => validateStage7RuntimeSecretsInput(extendedInput, { now: NOW }),
    'E7_RUNTIME_SECRETS_INPUT_SCHEMA_INVALID',
  );

  const duplicateFilename = path.join(selfTestRoot, 'duplicate.json');
  writeFileSync(duplicateFilename, '{"schemaVersion":1,"schemaVersion":1}', 'utf8');
  rejects(
    () =>
      validateStage7RuntimeSecretsFile({
        inputFilename: duplicateFilename,
        now: NOW,
        privateRoot: selfTestRoot,
      }),
    'E7_RUNTIME_SECRETS_INPUT_JSON_INVALID',
  );

  rejects(
    () =>
      validateStage7RuntimeSecretsFile({
        inputFilename: path.join(workspaceRoot, 'outside-private.json'),
        now: NOW,
        privateRoot: selfTestRoot,
      }),
    'E7_RUNTIME_SECRETS_PRIVATE_PATH_INVALID',
  );

  const invalidAccountInput = createStage7RuntimeSecretsInput(ACCOUNT_ID);
  invalidAccountInput.accountId = '123456789012';
  rejects(
    () => validateStage7RuntimeSecretsInput(invalidAccountInput, { allowIncompleteSandbox: true }),
    'E7_RUNTIME_SECRETS_INPUT_SCHEMA_INVALID',
  );
} finally {
  rmSync(selfTestRoot, { recursive: true, force: true });
}

process.stdout.write(
  `runtime-secrets-self-test: PASS (${assertions} assertions; ${canaries} rejection canaries)\n`,
);
