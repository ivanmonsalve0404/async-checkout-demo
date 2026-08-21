import { spawnSync } from 'node:child_process';
import { Buffer } from 'node:buffer';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { normalizePnpmScriptArguments } from './cli-arguments.mjs';
import { canonicalJson, workspaceRoot } from './core.mjs';

const INPUT_KIND = 'STAGE7_RUNTIME_SECRETS_INPUT';
const RESULT_KIND = 'STAGE7_RUNTIME_SECRETS_RESULT';
const QUOTE_TTL_SECONDS = 900;
const MAX_INPUT_BYTES = 64 * 1_024;
const MAX_AWS_OUTPUT_BYTES = 2 * 1_024 * 1_024;
const MAX_WOMPI_RESPONSE_BYTES = 256 * 1_024;
const WOMPI_SANDBOX_MERCHANT_ORIGIN = 'https://sandbox.wompi.co';
const PRIVATE_ROOT = path.join(workspaceRoot, '.stage7', 'private');
const AWS_PROFILE = /^[A-Za-z0-9_+=,.@-]{1,128}$/u;
const ACCOUNT_ID = /^(?!0{12}$)[0-9]{12}$/u;
const SECRET_VERSION_ID = /^[A-Za-z0-9-]{32,64}$/u;
const BASE64URL_SECRET = /^[A-Za-z0-9_-]{43,128}$/u;
const PUBLIC_KEY = /^pub_test_[A-Za-z0-9_-]{8,128}$/u;
const PRIVATE_KEY = /^prv_test_[A-Za-z0-9_-]{8,256}$/u;
const INTEGRITY_SECRET = /^test_integrity_[A-Za-z0-9_-]{8,256}$/u;

export const stage7RuntimeSecretTargets = Object.freeze({
  full: Object.freeze({
    description: 'Stage 7 FULL and baseline assessment runtime secret',
    region: 'us-east-1',
    scopeTag: 'FULL_BASELINE',
    secretName: 'checkout/assessment-release/runtime',
  }),
  prerelease: Object.freeze({
    description: 'Stage 7 PRERELEASE assessment runtime secret',
    region: 'us-east-2',
    scopeTag: 'PRERELEASE',
    secretName: 'checkout/assessment-prerelease/runtime',
  }),
});

const targetNames = Object.freeze(Object.keys(stage7RuntimeSecretTargets));
const sandboxKeys = Object.freeze([
  'integritySecret',
  'personalDataAcceptanceToken',
  'personalDataPermalink',
  'privateKey',
  'publicKey',
  'termsAcceptanceToken',
  'termsPermalink',
]);
const sandboxAcceptanceKeys = Object.freeze([
  'personalDataAcceptanceToken',
  'personalDataPermalink',
  'termsAcceptanceToken',
  'termsPermalink',
]);
const generatedKeys = Object.freeze(['prereleaseOriginToken', 'runtimeSecurityRootKey']);
const runtimeSecretKeys = Object.freeze([...sandboxKeys, ...generatedKeys].sort());

export class Stage7RuntimeSecretsError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7RuntimeSecretsError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7RuntimeSecretsError(code);
};

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const isRecord = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
const cloneJson = (value) => JSON.parse(JSON.stringify(value));
const hasExactKeys = (value, expected) =>
  isRecord(value) &&
  Object.keys(value).length === expected.length &&
  expected.every((key) => Object.hasOwn(value, key));
const hasOnlyKeys = (value, expected) =>
  isRecord(value) && Object.keys(value).every((key) => expected.includes(key));

const canonicalBase64Url = (value) =>
  typeof value === 'string' &&
  BASE64URL_SECRET.test(value) &&
  Buffer.from(value, 'base64url').toString('base64url') === value;

const canonicalJwtSegment = (value) =>
  value.length > 0 &&
  /^[A-Za-z0-9_-]+$/u.test(value) &&
  Buffer.from(value, 'base64url').toString('base64url') === value;

const sandboxCredentialsValid = (sandbox) =>
  typeof sandbox.publicKey === 'string' &&
  PUBLIC_KEY.test(sandbox.publicKey) &&
  typeof sandbox.privateKey === 'string' &&
  PRIVATE_KEY.test(sandbox.privateKey) &&
  typeof sandbox.integritySecret === 'string' &&
  INTEGRITY_SECRET.test(sandbox.integritySecret);

export const isProviderAcceptanceTokenUsable = (
  value,
  { now = new Date(), minimumRemainingSeconds = 0 } = {},
) => {
  if (
    typeof value !== 'string' ||
    value.length < 8 ||
    value.length > 8_192 ||
    !Number.isFinite(now.getTime()) ||
    !Number.isSafeInteger(minimumRemainingSeconds) ||
    minimumRemainingSeconds < 0
  ) {
    return false;
  }
  if (!value.includes('.')) return true;
  const segments = value.split('.');
  if (segments.length !== 3 || !segments.every(canonicalJwtSegment)) return false;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(segments[1], 'base64url').toString('utf8'));
  } catch {
    return false;
  }
  if (!isRecord(payload)) return false;
  if (payload.exp === undefined) return true;
  return (
    Number.isSafeInteger(payload.exp) &&
    payload.exp > 0 &&
    payload.exp > now.getTime() / 1_000 + minimumRemainingSeconds
  );
};

export const isWompiProviderPermalink = (value) => {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2_048) return false;
  try {
    const parsed = new URL(value);
    const officialHost =
      parsed.hostname === 'wompi.co' ||
      parsed.hostname.endsWith('.wompi.co') ||
      parsed.hostname === 'wompi.com' ||
      parsed.hostname.endsWith('.wompi.com');
    return (
      parsed.protocol === 'https:' &&
      officialHost &&
      parsed.username.length === 0 &&
      parsed.password.length === 0 &&
      parsed.toString() === value
    );
  } catch {
    return false;
  }
};

const validateSandbox = (sandbox, { allowIncomplete, now }) => {
  if (!hasExactKeys(sandbox, sandboxKeys)) fail('E7_RUNTIME_SECRETS_INPUT_SCHEMA_INVALID');
  if (
    allowIncomplete &&
    (sandboxKeys.every((key) => sandbox[key] === null) ||
      (sandboxCredentialsValid(sandbox) &&
        sandboxAcceptanceKeys.every((key) => sandbox[key] === null)))
  ) {
    return;
  }
  if (
    !sandboxCredentialsValid(sandbox) ||
    !isProviderAcceptanceTokenUsable(sandbox.termsAcceptanceToken, {
      now,
      minimumRemainingSeconds: QUOTE_TTL_SECONDS,
    }) ||
    !isWompiProviderPermalink(sandbox.termsPermalink) ||
    !isProviderAcceptanceTokenUsable(sandbox.personalDataAcceptanceToken, {
      now,
      minimumRemainingSeconds: QUOTE_TTL_SECONDS,
    }) ||
    !isWompiProviderPermalink(sandbox.personalDataPermalink)
  ) {
    fail('E7_RUNTIME_SECRETS_SANDBOX_INVALID');
  }
};

export const validateStage7RuntimeSecretsInput = (
  value,
  { allowIncompleteSandbox = false, allowMissingGenerated = false, now = new Date() } = {},
) => {
  if (
    !hasExactKeys(value, ['accountId', 'kind', 'sandbox', 'schemaVersion', 'stage', 'targets']) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== INPUT_KIND ||
    !ACCOUNT_ID.test(value.accountId) ||
    value.accountId === '123456789012' ||
    !hasExactKeys(value.targets, targetNames)
  ) {
    fail('E7_RUNTIME_SECRETS_INPUT_SCHEMA_INVALID');
  }
  validateSandbox(value.sandbox, { allowIncomplete: allowIncompleteSandbox, now });
  for (const targetName of targetNames) {
    const target = value.targets[targetName];
    if (!hasOnlyKeys(target, generatedKeys)) fail('E7_RUNTIME_SECRETS_INPUT_SCHEMA_INVALID');
    if (!allowMissingGenerated && !hasExactKeys(target, generatedKeys)) {
      fail('E7_RUNTIME_SECRETS_INPUT_SCHEMA_INVALID');
    }
    for (const key of generatedKeys) {
      if (Object.hasOwn(target, key) && !canonicalBase64Url(target[key])) {
        fail('E7_RUNTIME_SECRETS_GENERATED_VALUE_INVALID');
      }
    }
  }
  return value;
};

const generatedSecret = () => randomBytes(32).toString('base64url');

export const createStage7RuntimeSecretsInput = (accountId) => {
  if (!ACCOUNT_ID.test(accountId) || accountId === '123456789012') {
    fail('E7_RUNTIME_SECRETS_ACCOUNT_ID_INVALID');
  }
  return {
    schemaVersion: 1,
    stage: 7,
    kind: INPUT_KIND,
    accountId,
    targets: Object.fromEntries(
      targetNames.map((targetName) => [
        targetName,
        {
          runtimeSecurityRootKey: generatedSecret(),
          prereleaseOriginToken: generatedSecret(),
        },
      ]),
    ),
    sandbox: Object.fromEntries(sandboxKeys.map((key) => [key, null])),
  };
};

const completeGeneratedValues = (input) => {
  const completed = cloneJson(input);
  let changed = false;
  for (const targetName of targetNames) {
    for (const key of generatedKeys) {
      if (!Object.hasOwn(completed.targets[targetName], key)) {
        completed.targets[targetName][key] = generatedSecret();
        changed = true;
      }
    }
  }
  return { changed, value: completed };
};

const ensureInsideWorkspace = (candidate) => {
  const relative = path.relative(workspaceRoot, candidate);
  if (relative.startsWith(`..${path.sep}`) || relative === '..' || path.isAbsolute(relative)) {
    fail('E7_RUNTIME_SECRETS_PRIVATE_PATH_INVALID');
  }
};

const rejectSymlinkPath = (candidate) => {
  ensureInsideWorkspace(candidate);
  const relative = path.relative(workspaceRoot, candidate);
  let current = workspaceRoot;
  for (const segment of relative.split(path.sep)) {
    current = path.join(current, segment);
    if (existsSync(current) && lstatSync(current).isSymbolicLink()) {
      fail('E7_RUNTIME_SECRETS_PRIVATE_PATH_INVALID');
    }
  }
};

let windowsAclIdentities;
const resolveWindowsAclIdentities = () => {
  if (windowsAclIdentities !== undefined) return windowsAclIdentities;
  const identity = spawnSync('whoami.exe', ['/user', '/fo', 'csv', '/nh'], {
    encoding: 'utf8',
    timeout: 10_000,
    windowsHide: true,
  });
  const match =
    identity.status === 0 && typeof identity.stdout === 'string'
      ? /^"[^"]+","(S-[0-9-]+)"\s*$/u.exec(identity.stdout.trim())
      : null;
  const username = process.env.USERNAME;
  const domain = process.env.USERDOMAIN;
  if (
    match === null ||
    typeof username !== 'string' ||
    !/^[A-Za-z0-9._ -]{1,64}$/u.test(username) ||
    (domain !== undefined && !/^[A-Za-z0-9._ -]{1,64}$/u.test(domain))
  ) {
    fail('E7_RUNTIME_SECRETS_PRIVATE_ACL_FAILED');
  }
  const operator = domain === undefined ? username : `${domain}\\${username}`;
  windowsAclIdentities = Object.freeze([
    ...new Set([match[1], operator, 'S-1-5-18', 'S-1-5-32-544']),
  ]);
  return windowsAclIdentities;
};

const WINDOWS_EXACT_ACL_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$targetPath = $env:STAGE7_PRIVATE_ACL_TARGET
$targetKind = $env:STAGE7_PRIVATE_ACL_KIND
$identitySource = $env:STAGE7_PRIVATE_ACL_IDENTITIES
if ([string]::IsNullOrWhiteSpace($targetPath) -or
    @('directory', 'file') -notcontains $targetKind -or
    [string]::IsNullOrWhiteSpace($identitySource)) { throw 'ACL_INPUT_INVALID' }
$identityDocument = ConvertFrom-Json -InputObject $identitySource
if (@($identityDocument.PSObject.Properties.Name).Count -ne 1 -or
    -not $identityDocument.PSObject.Properties['identities']) {
  throw 'ACL_IDENTITIES_INVALID'
}
$identityValues = @($identityDocument.identities)
$translated = @(
  foreach ($identity in $identityValues) {
    $identityText = [string]$identity
    if ($identityText -match '^S-[0-9-]+$') {
      [System.Security.Principal.SecurityIdentifier]::new($identityText)
    } else {
      [System.Security.Principal.NTAccount]::new($identityText).Translate(
        [System.Security.Principal.SecurityIdentifier]
      )
    }
  }
)
$sids = @($translated | Group-Object -Property Value | ForEach-Object { $_.Group[0] })
if ($sids.Count -lt 3) { throw 'ACL_IDENTITIES_INVALID' }
$targetInfo = if ($targetKind -eq 'directory') {
  [System.IO.DirectoryInfo]::new($targetPath)
} else {
  [System.IO.FileInfo]::new($targetPath)
}
$acl = $targetInfo.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
$acl.SetAccessRuleProtection($true, $false)
foreach ($existingRule in @($acl.Access)) {
  [void]$acl.RemoveAccessRuleSpecific($existingRule)
}
$inheritance = if ($targetKind -eq 'directory') {
  [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
} else {
  [System.Security.AccessControl.InheritanceFlags]::None
}
foreach ($sid in $sids) {
  $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    $inheritance,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
  [void]$acl.AddAccessRule($rule)
}
$targetInfo.SetAccessControl($acl)
$verified = $targetInfo.GetAccessControl(
  [System.Security.AccessControl.AccessControlSections]::Access
)
$rules = @($verified.Access)
$expectedSids = @($sids | ForEach-Object { $_.Value } | Sort-Object -Unique)
$actualSids = @(
  $rules | ForEach-Object {
    $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
  } | Sort-Object -Unique
)
$differences = @(Compare-Object -ReferenceObject $expectedSids -DifferenceObject $actualSids)
$expectedInheritance = [int]$inheritance
$invalidRule = @(
  $rules | Where-Object {
    $_.IsInherited -or
    $_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
    [int64]$_.FileSystemRights -ne [int64][System.Security.AccessControl.FileSystemRights]::FullControl -or
    [int]$_.InheritanceFlags -ne $expectedInheritance -or
    $_.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
  }
).Count -ne 0
if (-not $verified.AreAccessRulesProtected -or
    -not $verified.AreAccessRulesCanonical -or
    $rules.Count -ne $expectedSids.Count -or
    $differences.Count -ne 0 -or
    $invalidRule) { throw 'ACL_EXACT_VALIDATION_FAILED' }
[Console]::Out.Write('ACL_EXACT')
`;

const hardenPrivatePath = (candidate, { directory }) => {
  chmodSync(candidate, directory ? 0o700 : 0o600);
  if (process.platform !== 'win32') return;
  const result = spawnSync(
    'powershell.exe',
    [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-Command',
      WINDOWS_EXACT_ACL_SCRIPT,
    ],
    {
      encoding: 'utf8',
      env: {
        ...process.env,
        STAGE7_PRIVATE_ACL_IDENTITIES: JSON.stringify({
          identities: resolveWindowsAclIdentities(),
        }),
        STAGE7_PRIVATE_ACL_KIND: directory ? 'directory' : 'file',
        STAGE7_PRIVATE_ACL_TARGET: candidate,
      },
      timeout: 15_000,
      windowsHide: true,
    },
  );
  if (result.status !== 0 || result.stdout.trim() !== 'ACL_EXACT') {
    fail('E7_RUNTIME_SECRETS_PRIVATE_ACL_FAILED');
  }
};

const resolvePrivateInput = (
  inputFilename,
  privateRoot = PRIVATE_ROOT,
  { createRoot = false } = {},
) => {
  const root = path.resolve(privateRoot);
  ensureInsideWorkspace(root);
  if (root === workspaceRoot) fail('E7_RUNTIME_SECRETS_PRIVATE_PATH_INVALID');
  rejectSymlinkPath(path.dirname(root));
  if (createRoot) mkdirSync(root, { recursive: true, mode: 0o700 });
  if (!existsSync(root) || !lstatSync(root).isDirectory()) {
    fail('E7_RUNTIME_SECRETS_PRIVATE_PATH_INVALID');
  }
  rejectSymlinkPath(root);
  hardenPrivatePath(root, { directory: true });
  const filename = path.resolve(inputFilename);
  if (
    path.dirname(filename) !== root ||
    path.extname(filename).toLowerCase() !== '.json' ||
    path.basename(filename).startsWith('.')
  ) {
    fail('E7_RUNTIME_SECRETS_PRIVATE_PATH_INVALID');
  }
  if (existsSync(filename)) {
    rejectSymlinkPath(filename);
    if (!lstatSync(filename).isFile()) fail('E7_RUNTIME_SECRETS_PRIVATE_PATH_INVALID');
    hardenPrivatePath(filename, { directory: false });
  }
  return filename;
};

const privateSource = (value) => `${JSON.stringify(value, null, 2)}\n`;

const writePrivateFileExclusive = (filename, value) => {
  writeFileSync(filename, privateSource(value), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  hardenPrivatePath(filename, { directory: false });
};

const scrubAndRemovePrivateFile = (filename) => {
  if (!existsSync(filename)) return;
  try {
    writeFileSync(filename, '', { encoding: 'utf8', flag: 'w', mode: 0o600 });
    chmodSync(filename, 0o600);
  } catch {
    fail('E7_RUNTIME_SECRETS_PRIVATE_SCRUB_FAILED');
  }
  rmSync(filename, { force: true });
  if (existsSync(filename) && statSync(filename).size !== 0) {
    fail('E7_RUNTIME_SECRETS_PRIVATE_SCRUB_FAILED');
  }
};

const replacePrivateFile = (filename, value) => {
  const temporary = path.join(
    path.dirname(filename),
    `.${path.basename(filename)}.${randomUUID()}.tmp`,
  );
  try {
    writePrivateFileExclusive(temporary, value);
    renameSync(temporary, filename);
    hardenPrivatePath(filename, { directory: false });
  } catch {
    fail('E7_RUNTIME_SECRETS_PRIVATE_WRITE_FAILED');
  } finally {
    scrubAndRemovePrivateFile(temporary);
  }
};

const readPrivateInput = (
  filename,
  { now, allowIncompleteSandbox = false, allowMissingGenerated },
) => {
  const size = statSync(filename).size;
  if (size <= 0 || size > MAX_INPUT_BYTES) fail('E7_RUNTIME_SECRETS_INPUT_SIZE_INVALID');
  let value;
  try {
    value = parseStrictJsonSource(readFileSync(filename), { scanForbiddenData: false });
  } catch {
    fail('E7_RUNTIME_SECRETS_INPUT_JSON_INVALID');
  }
  return validateStage7RuntimeSecretsInput(value, {
    allowIncompleteSandbox,
    allowMissingGenerated,
    now,
  });
};

const secretDocument = (input, targetName) => {
  const document = {
    ...input.sandbox,
    ...input.targets[targetName],
  };
  if (!hasExactKeys(document, runtimeSecretKeys)) fail('E7_RUNTIME_SECRETS_DOCUMENT_INVALID');
  return document;
};

const localValidationResult = (input, status) => ({
  kind: RESULT_KIND,
  schemaVersion: 1,
  stage: 7,
  status,
  inputSha256: sha256(canonicalJson(input)),
  targets: Object.fromEntries(
    targetNames.map((targetName) => [
      targetName,
      { secretDocumentSha256: sha256(canonicalJson(secretDocument(input, targetName))) },
    ]),
  ),
});

const wompiMerchantUrl = (publicKey) =>
  `${WOMPI_SANDBOX_MERCHANT_ORIGIN}/v1/merchants/${encodeURIComponent(publicKey)}`;

export const readWompiSandboxMerchant = async (url) => {
  if (
    typeof url !== 'string' ||
    !/^https:\/\/sandbox\.wompi\.co\/v1\/merchants\/pub_test_[A-Za-z0-9_-]{8,128}$/u.test(url)
  ) {
    fail('E7_RUNTIME_SECRETS_WOMPI_URL_INVALID');
  }
  let response;
  try {
    response = await globalThis.fetch(url, {
      headers: { accept: 'application/json' },
      method: 'GET',
      redirect: 'error',
      signal: globalThis.AbortSignal.timeout(10_000),
    });
  } catch {
    fail('E7_RUNTIME_SECRETS_WOMPI_REQUEST_FAILED');
  }
  const contentLength = response.headers.get('content-length');
  if (
    contentLength !== null &&
    (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength) ||
      Number(contentLength) > MAX_WOMPI_RESPONSE_BYTES)
  ) {
    fail('E7_RUNTIME_SECRETS_WOMPI_RESPONSE_INVALID');
  }
  if (response.body === null) fail('E7_RUNTIME_SECRETS_WOMPI_RESPONSE_INVALID');
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.byteLength;
      if (total > MAX_WOMPI_RESPONSE_BYTES) {
        await reader.cancel();
        fail('E7_RUNTIME_SECRETS_WOMPI_RESPONSE_INVALID');
      }
      chunks.push(Buffer.from(part.value));
    }
  } catch (error) {
    if (error instanceof Stage7RuntimeSecretsError) throw error;
    fail('E7_RUNTIME_SECRETS_WOMPI_REQUEST_FAILED');
  }
  return {
    body: Buffer.concat(chunks, total),
    contentType: response.headers.get('content-type'),
    redirected: response.redirected,
    status: response.status,
    url: response.url,
  };
};

const parseWompiMerchantAcceptances = (response, expectedUrl, now) => {
  if (
    !isRecord(response) ||
    response.status !== 200 ||
    response.redirected !== false ||
    response.url !== expectedUrl ||
    typeof response.contentType !== 'string' ||
    !/^application\/json(?:\s*;|$)/iu.test(response.contentType) ||
    !Buffer.isBuffer(response.body) ||
    response.body.byteLength === 0 ||
    response.body.byteLength > MAX_WOMPI_RESPONSE_BYTES
  ) {
    fail('E7_RUNTIME_SECRETS_WOMPI_RESPONSE_INVALID');
  }
  let payload;
  try {
    payload = parseStrictJsonSource(response.body, { scanForbiddenData: false });
  } catch {
    fail('E7_RUNTIME_SECRETS_WOMPI_RESPONSE_INVALID');
  }
  const data = isRecord(payload) ? payload.data : undefined;
  const terms = isRecord(data) ? data.presigned_acceptance : undefined;
  const personalData = isRecord(data) ? data.presigned_personal_data_auth : undefined;
  if (
    !hasExactKeys(terms, ['acceptance_token', 'permalink', 'type']) ||
    terms.type !== 'END_USER_POLICY' ||
    !hasExactKeys(personalData, ['acceptance_token', 'permalink', 'type']) ||
    personalData.type !== 'PERSONAL_DATA_AUTH'
  ) {
    fail('E7_RUNTIME_SECRETS_WOMPI_RESPONSE_INVALID');
  }
  const acceptances = {
    termsAcceptanceToken: terms.acceptance_token,
    termsPermalink: terms.permalink,
    personalDataAcceptanceToken: personalData.acceptance_token,
    personalDataPermalink: personalData.permalink,
  };
  if (
    !isProviderAcceptanceTokenUsable(acceptances.termsAcceptanceToken, {
      now,
      minimumRemainingSeconds: QUOTE_TTL_SECONDS,
    }) ||
    !isWompiProviderPermalink(acceptances.termsPermalink) ||
    !isProviderAcceptanceTokenUsable(acceptances.personalDataAcceptanceToken, {
      now,
      minimumRemainingSeconds: QUOTE_TTL_SECONDS,
    }) ||
    !isWompiProviderPermalink(acceptances.personalDataPermalink)
  ) {
    fail('E7_RUNTIME_SECRETS_WOMPI_RESPONSE_INVALID');
  }
  return acceptances;
};

const safeEqual = (left, right) => {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
};

const parseAwsJson = (source) => {
  if (typeof source !== 'string' || Buffer.byteLength(source) > MAX_AWS_OUTPUT_BYTES) {
    fail('E7_RUNTIME_SECRETS_AWS_RESPONSE_INVALID');
  }
  try {
    const value = JSON.parse(source);
    if (!isRecord(value)) fail('E7_RUNTIME_SECRETS_AWS_RESPONSE_INVALID');
    return value;
  } catch (error) {
    if (error instanceof Stage7RuntimeSecretsError) throw error;
    fail('E7_RUNTIME_SECRETS_AWS_RESPONSE_INVALID');
  }
};

const resolveAwsCommand = (environment = process.env) => {
  if (environment.AWS_CLI_PATH !== undefined) {
    if (!path.isAbsolute(environment.AWS_CLI_PATH) || !existsSync(environment.AWS_CLI_PATH)) {
      fail('E7_RUNTIME_SECRETS_AWS_CLI_INVALID');
    }
    return environment.AWS_CLI_PATH;
  }
  if (process.platform === 'win32' && environment.LOCALAPPDATA !== undefined) {
    const candidate = path.join(
      environment.LOCALAPPDATA,
      'Programs',
      'Amazon',
      'AWSCLIV2',
      'aws.exe',
    );
    if (existsSync(candidate)) return candidate;
  }
  return 'aws';
};

export const executeAwsCli = (arguments_, { environment = process.env } = {}) => {
  const result = spawnSync(resolveAwsCommand(environment), arguments_, {
    encoding: 'utf8',
    env: { ...environment, AWS_CLI_AUTO_PROMPT: 'off', AWS_PAGER: '' },
    maxBuffer: MAX_AWS_OUTPUT_BYTES,
    timeout: 45_000,
    windowsHide: true,
  });
  return {
    status: result.status,
    stderr: typeof result.stderr === 'string' ? result.stderr : '',
    stdout: typeof result.stdout === 'string' ? result.stdout : '',
  };
};

const awsArguments = (profile, service, command, commandArguments) => [
  '--profile',
  profile,
  '--no-cli-pager',
  '--color',
  'off',
  service,
  command,
  ...commandArguments,
  '--output',
  'json',
];

const awsCall = (executor, profile, service, command, commandArguments) => {
  const result = executor(awsArguments(profile, service, command, commandArguments));
  if (!isRecord(result) || !(Number.isInteger(result.status) || result.status === null)) {
    fail('E7_RUNTIME_SECRETS_AWS_EXECUTOR_INVALID');
  }
  if (result.status !== 0) {
    const stderr = typeof result.stderr === 'string' ? result.stderr : '';
    if (/ResourceNotFoundException/u.test(stderr)) {
      fail('E7_RUNTIME_SECRETS_AWS_NOT_FOUND');
    }
    if (/ResourceExistsException/u.test(stderr)) {
      fail('E7_RUNTIME_SECRETS_AWS_ALREADY_EXISTS');
    }
    fail('E7_RUNTIME_SECRETS_AWS_CALL_FAILED');
  }
  return parseAwsJson(result.stdout);
};

const requiredTags = (target) => ({
  ManagedBy: 'stage7-runtime-secrets-cli',
  Scope: target.scopeTag,
  Stage: '7',
});

const validSecretArn = (arn, target, accountId) => {
  if (typeof arn !== 'string') return false;
  const prefix = `arn:aws:secretsmanager:${target.region}:${accountId}:secret:${target.secretName}-`;
  return arn.startsWith(prefix) && /^[A-Za-z0-9]{6}$/u.test(arn.slice(prefix.length));
};

const validateDescription = (description, target, accountId) => {
  if (
    description.Name !== target.secretName ||
    !validSecretArn(description.ARN, target, accountId) ||
    description.DeletedDate !== undefined ||
    description.RotationEnabled === true ||
    !Array.isArray(description.Tags)
  ) {
    fail('E7_RUNTIME_SECRETS_AWS_BINDING_INVALID');
  }
  const tags = new Map(
    description.Tags.map((tag) => [
      isRecord(tag) ? tag.Key : undefined,
      isRecord(tag) ? tag.Value : undefined,
    ]),
  );
  for (const [key, value] of Object.entries(requiredTags(target))) {
    if (tags.get(key) !== value) fail('E7_RUNTIME_SECRETS_AWS_BINDING_INVALID');
  }
};

const validateExistingSecret = ({ accountId, document, executor, profile, target }) => {
  const description = awsCall(executor, profile, 'secretsmanager', 'describe-secret', [
    '--secret-id',
    target.secretName,
    '--region',
    target.region,
  ]);
  validateDescription(description, target, accountId);
  const response = awsCall(executor, profile, 'secretsmanager', 'get-secret-value', [
    '--secret-id',
    description.ARN,
    '--version-stage',
    'AWSCURRENT',
    '--region',
    target.region,
  ]);
  if (
    response.ARN !== description.ARN ||
    response.Name !== target.secretName ||
    !SECRET_VERSION_ID.test(response.VersionId ?? '') ||
    !Array.isArray(response.VersionStages) ||
    !response.VersionStages.includes('AWSCURRENT') ||
    typeof response.SecretString !== 'string' ||
    response.SecretBinary !== undefined
  ) {
    fail('E7_RUNTIME_SECRETS_AWS_RESPONSE_INVALID');
  }
  let existing;
  try {
    existing = parseStrictJsonSource(Buffer.from(response.SecretString, 'utf8'), {
      scanForbiddenData: false,
    });
  } catch {
    fail('E7_RUNTIME_SECRETS_EXISTING_DOCUMENT_INVALID');
  }
  if (!hasExactKeys(existing, runtimeSecretKeys)) {
    fail('E7_RUNTIME_SECRETS_EXISTING_DOCUMENT_INVALID');
  }
  const expectedSource = canonicalJson(document);
  const existingSource = canonicalJson(existing);
  if (!safeEqual(expectedSource, existingSource)) {
    fail('E7_RUNTIME_SECRETS_EXISTING_VALUE_MISMATCH');
  }
  return {
    arn: description.ARN,
    secretDocumentSha256: sha256(expectedSource),
    versionId: response.VersionId,
  };
};

const createSecret = ({ document, executor, profile, target, privateRoot }) => {
  const payloadFilename = path.join(privateRoot, `.runtime-secret-${randomUUID()}.json`);
  try {
    writePrivateFileExclusive(payloadFilename, document);
    awsCall(executor, profile, 'secretsmanager', 'create-secret', [
      '--name',
      target.secretName,
      '--description',
      target.description,
      '--secret-string',
      `file://${payloadFilename}`,
      '--tags',
      ...Object.entries(requiredTags(target)).map(([Key, Value]) => `Key=${Key},Value=${Value}`),
      '--region',
      target.region,
    ]);
  } finally {
    scrubAndRemovePrivateFile(payloadFilename);
  }
};

const createOrValidateSecret = (options) => {
  let created = false;
  try {
    return {
      action: 'VERIFIED_EXISTING',
      ...validateExistingSecret(options),
    };
  } catch (error) {
    if (error?.code !== 'E7_RUNTIME_SECRETS_AWS_NOT_FOUND') throw error;
  }
  try {
    createSecret(options);
    created = true;
  } catch (error) {
    if (error?.code !== 'E7_RUNTIME_SECRETS_AWS_ALREADY_EXISTS') throw error;
  }
  return {
    action: created ? 'CREATED' : 'VERIFIED_EXISTING_AFTER_RACE',
    ...validateExistingSecret(options),
  };
};

export const initializeStage7RuntimeSecretsFile = ({
  accountId,
  inputFilename,
  privateRoot = PRIVATE_ROOT,
}) => {
  const filename = resolvePrivateInput(inputFilename, privateRoot, { createRoot: true });
  if (existsSync(filename)) fail('E7_RUNTIME_SECRETS_INPUT_ALREADY_EXISTS');
  const value = createStage7RuntimeSecretsInput(accountId);
  writePrivateFileExclusive(filename, value);
  return {
    kind: RESULT_KIND,
    schemaVersion: 1,
    stage: 7,
    status: 'INITIALIZED_PRIVATE_INPUT',
    inputSha256: sha256(canonicalJson(value)),
  };
};

export const hydrateStage7RuntimeSecretsFile = async ({
  inputFilename,
  merchantReader = readWompiSandboxMerchant,
  now = new Date(),
  privateRoot = PRIVATE_ROOT,
}) => {
  if (typeof merchantReader !== 'function') fail('E7_RUNTIME_SECRETS_WOMPI_READER_INVALID');
  const filename = resolvePrivateInput(inputFilename, privateRoot);
  const input = readPrivateInput(filename, {
    allowIncompleteSandbox: true,
    allowMissingGenerated: false,
    now,
  });
  if (!sandboxCredentialsValid(input.sandbox)) {
    fail('E7_RUNTIME_SECRETS_SANDBOX_CREDENTIALS_REQUIRED');
  }
  if (sandboxAcceptanceKeys.every((key) => input.sandbox[key] !== null)) {
    validateStage7RuntimeSecretsInput(input, { now });
    return localValidationResult(input, 'ALREADY_HYDRATED');
  }
  if (!sandboxAcceptanceKeys.every((key) => input.sandbox[key] === null)) {
    fail('E7_RUNTIME_SECRETS_SANDBOX_ACCEPTANCES_PARTIAL');
  }
  const expectedUrl = wompiMerchantUrl(input.sandbox.publicKey);
  let response;
  try {
    response = await merchantReader(expectedUrl);
  } catch (error) {
    if (error instanceof Stage7RuntimeSecretsError) throw error;
    fail('E7_RUNTIME_SECRETS_WOMPI_REQUEST_FAILED');
  }
  const hydrated = cloneJson(input);
  Object.assign(hydrated.sandbox, parseWompiMerchantAcceptances(response, expectedUrl, now));
  validateStage7RuntimeSecretsInput(hydrated, { now });
  replacePrivateFile(filename, hydrated);
  return localValidationResult(hydrated, 'HYDRATED_PRIVATE_INPUT');
};

export const validateStage7RuntimeSecretsFile = ({
  inputFilename,
  now = new Date(),
  privateRoot = PRIVATE_ROOT,
}) => {
  const filename = resolvePrivateInput(inputFilename, privateRoot);
  const input = readPrivateInput(filename, { allowMissingGenerated: false, now });
  return localValidationResult(input, 'VALIDATED_LOCALLY');
};

export const materializeStage7RuntimeSecrets = ({
  executor = executeAwsCli,
  inputFilename,
  now = new Date(),
  privateRoot = PRIVATE_ROOT,
  profile,
}) => {
  if (typeof profile !== 'string' || !AWS_PROFILE.test(profile)) {
    fail('E7_RUNTIME_SECRETS_AWS_PROFILE_INVALID');
  }
  const filename = resolvePrivateInput(inputFilename, privateRoot);
  const draft = readPrivateInput(filename, { allowMissingGenerated: true, now });
  validateSandbox(draft.sandbox, { allowIncomplete: false, now });
  const completed = completeGeneratedValues(draft);
  validateStage7RuntimeSecretsInput(completed.value, { now });
  if (completed.changed) replacePrivateFile(filename, completed.value);
  const input = completed.value;
  const identity = awsCall(executor, profile, 'sts', 'get-caller-identity', [
    '--region',
    stage7RuntimeSecretTargets.full.region,
  ]);
  if (identity.Account !== input.accountId || typeof identity.Arn !== 'string') {
    fail('E7_RUNTIME_SECRETS_AWS_ACCOUNT_MISMATCH');
  }
  const targets = {};
  for (const targetName of targetNames) {
    const target = stage7RuntimeSecretTargets[targetName];
    targets[targetName] = createOrValidateSecret({
      accountId: input.accountId,
      document: secretDocument(input, targetName),
      executor,
      privateRoot: path.dirname(filename),
      profile,
      target,
    });
  }
  return {
    kind: RESULT_KIND,
    schemaVersion: 1,
    stage: 7,
    status: 'MATERIALIZED_AND_VERIFIED',
    inputSha256: sha256(canonicalJson(input)),
    targets,
  };
};

const parseFlags = (arguments_) => {
  const command = arguments_[0];
  const allowedByCommand = {
    hydrate: ['--input'],
    init: ['--account-id', '--input'],
    materialize: ['--input', '--profile'],
    validate: ['--input'],
  };
  const allowed = allowedByCommand[command];
  if (allowed === undefined || arguments_.length !== 1 + allowed.length * 2) {
    fail('E7_RUNTIME_SECRETS_COMMAND_INVALID');
  }
  const flags = {};
  for (let index = 1; index < arguments_.length; index += 2) {
    const key = arguments_[index];
    const value = arguments_[index + 1];
    if (!allowed.includes(key) || value === undefined || Object.hasOwn(flags, key)) {
      fail('E7_RUNTIME_SECRETS_ARGUMENTS_INVALID');
    }
    flags[key] = value;
  }
  if (!allowed.every((key) => Object.hasOwn(flags, key))) {
    fail('E7_RUNTIME_SECRETS_ARGUMENTS_INVALID');
  }
  return { command, flags };
};

const main = async () => {
  const arguments_ = normalizePnpmScriptArguments(process.argv.slice(2), { separatorIndex: 0 });
  const { command, flags } = parseFlags(arguments_);
  const common = { inputFilename: flags['--input'] };
  let result;
  if (command === 'init') {
    result = initializeStage7RuntimeSecretsFile({ ...common, accountId: flags['--account-id'] });
  } else if (command === 'hydrate') {
    result = await hydrateStage7RuntimeSecretsFile(common);
  } else if (command === 'validate') {
    result = validateStage7RuntimeSecretsFile(common);
  } else {
    result = materializeStage7RuntimeSecrets({ ...common, profile: flags['--profile'] });
  }
  process.stdout.write(`${canonicalJson(result)}\n`);
};

const direct =
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (direct) {
  main().catch((error) => {
    process.stderr.write(`${error?.code ?? 'E7_RUNTIME_SECRETS_FAILED'}\n`);
    process.exitCode = 1;
  });
}
