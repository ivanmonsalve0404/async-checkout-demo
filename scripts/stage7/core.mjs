import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  selfTestArtifactSanitizer,
  writeSanitizedJsonAtomic,
} from '../stage6/lib/artifact-sanitizer.mjs';
import { sha256, stage6Branch } from '../stage6/lib/evidence.mjs';
import { parseStrictJsonSource, selfTestStrictJson } from '../stage6/strict-json.mjs';
import {
  PrereleaseSafetyContractError,
  validatePrereleaseSafetyReadiness as validatePrereleaseSafetyReadinessContract,
} from './prerelease-safety-contract.mjs';

export const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const SEMVER = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const NODE_VERSION = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const PACKAGE_MANAGER = /^pnpm@(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const RELEASE_TAG =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const RUN_ID = /^e6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}$/u;
const ALIAS = /^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/u;
const STACK = /^[A-Za-z][A-Za-z0-9-]{1,127}$/u;
const AWS_REGION =
  /^(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:central|east|north|northeast|northwest|south|southeast|southwest|west)-[1-9]$/u;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u;
const HOSTED_ZONE_ID = /^Z[A-Z0-9]{5,31}$/u;
const CREDENTIAL_REFERENCE =
  /^arn:aws:(?:secretsmanager|ssm):[a-z0-9-]+:[0-9]{12}:(?:secret|parameter):?\/?[A-Za-z0-9/_+=.@-]{1,256}$/u;
const LAMBDA_FUNCTION_NAME = /^[A-Za-z0-9-_]{1,64}$/u;
const LAMBDA_ALIAS_NAME = /^[A-Za-z0-9-_]{1,128}$/u;
const LAMBDA_VERSION = /^[1-9][0-9]*$/u;
const S3_BUCKET = /^(?=.{3,63}$)(?![0-9]+(?:\.[0-9]+){3}$)[a-z0-9][a-z0-9.-]*[a-z0-9]$/u;
const S3_VERSION_ID = /^[A-Za-z0-9._~+/=-]{1,1024}$/u;
const CLOUDFRONT_DISTRIBUTION_ID = /^[A-Z0-9]{8,64}$/u;
const WEB_OBJECT_KEY =
  /^(?!\/)(?!.*\\)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$/u;
const AUTHORIZATION_SCOPES = [
  'NON_MUTATING_PLAN',
  'EPHEMERAL_PRERELEASE',
  'FULL_RELEASE_VERSIONED_UPDATE',
];
const ABORT_CRITERIA = [
  'ACCOUNT_MISMATCH',
  'REGION_MISMATCH',
  'SECRET_EXPOSURE',
  'PRODUCTION_PROVIDER',
  'STATEFUL_REPLACEMENT',
  'SMOKE_FAILURE',
  'ROLLBACK_FAILURE',
  'BUDGET_BREACH',
];
const REQUIRED_ABORT_CRITERIA = ABORT_CRITERIA.slice(0, 7);
const ARTIFACT_STATES = [
  'PLANNED',
  'IN_PROGRESS',
  'VERIFIED',
  'FAILED',
  'BLOCKED_AUTH',
  'NOT_APPLICABLE_APPROVED',
  'SUPERSEDED',
];
const EVIDENCE_STATES = ['NOT_RUN', 'PASS', 'FAIL', 'BLOCKED_AUTH', 'NOT_APPLICABLE_APPROVED'];
const GATE_STATES = ['NOT_RUN', 'PASS', 'FAIL', 'BLOCKED_AUTH'];

export const expectedStage7Stacks = (environment) => [
  `checkout-${environment}-data`,
  `checkout-${environment}-api`,
  `checkout-${environment}-observability`,
  `checkout-${environment}-web`,
];

const ARTIFACT_NAMES = [
  'Plan de release',
  'Manifiesto del candidato',
  'Preflight AWS',
  'Paquete IaC',
  'Revisión de cambios',
  'Identidad de despliegue',
  'Reporte DataStack',
  'Reporte ApiStack',
  'Reporte WebStack',
  'Reporte edge/TLS',
  'Reporte observabilidad',
  'Reporte costes',
  'Smoke post-deploy',
  'Validación sandbox',
  'Reporte de rollback',
  'Seguridad del repositorio',
  'README y release notes',
  'Índice de evidencias',
  'Evaluación de gates',
  'Handoff a etapa 8',
];

const EVIDENCE_NAMES = [
  'Autorización de release y alcance',
  'SHA/tag/lockfile congelados',
  'Checksums de artefactos',
  'Toolchain y versiones',
  'Cuenta y región confirmadas',
  'Identidad OIDC/sesión temporal',
  'Bootstrap CDK verificado',
  'Tests de IaC verdes',
  'cdk synth reproducible',
  'cdk diff/change set aprobado',
  'Reemplazos stateful = 0 o aprobación explícita',
  'IAM broadening revisado',
  'Secret/config references validadas',
  'DataStack desplegado',
  'Tabla y cifrado/config aprobados',
  'Seed idempotente',
  'ApiStack desplegado',
  'Lambda/version/alias registrados',
  'Health y readiness API',
  'OpenAPI/Swagger público sanitizado',
  'Reconciliador programado verificado',
  'WebStack desplegado',
  'Bucket no público',
  'OAC y policy restringida',
  'CloudFront HTTPS operativo',
  'Assets versionados y política de caché',
  'Runtime config sin secretos',
  'CORS exacto',
  'Security headers reales',
  'Cookies reales seguras',
  'Logs estructurados y redacción',
  'Dashboard y métricas',
  'Alarmas verificadas',
  'Budget y alertas',
  'Smoke de catálogo/producto',
  'Smoke de checkout completo',
  'Aprobado: stock/entrega únicos',
  'Declined/error: sin stock/entrega',
  'Refresh durante progreso/PENDING',
  'Replay/doble clic idempotente',
  'Sandbox smoke autorizado',
  'Cross-browser focal post-deploy',
  'Accesibilidad focal post-deploy',
  'Lighthouse/performance real',
  'DAST/headers real autorizado',
  'Rollback frontend',
  'Rollback API',
  'Verificación posterior al rollback',
  'Re-promoción del candidato',
  'Secret scan de árbol e historial',
  'README y URLs finales',
  'Historial/commits visibles',
  'Scorecard de rúbrica enlazado',
  'Cleanup/runbook',
  'GATE-E7-01',
  'GATE-E7-02',
  'GATE-E7-03 y handoff',
];

export const STAGE7_ARTIFACTS = ARTIFACT_NAMES.map((name, index) => ({
  id: `ART-REL-${String(index + 1).padStart(2, '0')}`,
  name,
}));
export const STAGE7_EVIDENCE = EVIDENCE_NAMES.map((name, index) => ({
  id: `EVD-E7-${String(index + 1).padStart(2, '0')}`,
  name,
}));
export const STAGE7_AUDITS = Array.from({ length: 73 }, (_, index) => ({
  id: `AUD-E7-${String(index + 1).padStart(2, '0')}`,
}));
export const STAGE7_BUILD_OUTPUTS = Object.freeze({
  web: 'output/release/build/web',
  api: 'output/release/build/api/index.js',
  worker: 'output/release/build/worker/index.js',
  iac: 'output/release/build/iac',
});
export const STAGE7_REPORT_HEADINGS = [
  'Resumen ejecutivo',
  'Estado de entrada y GATE-E6-03',
  'Release ID, SHA, tag y checksums',
  'Autorizaciones y ventana',
  'Cuenta, región e identidad',
  'Toolchain y bootstrap',
  'IaC synth, tests, diff y drift',
  'IAM/OIDC',
  'Configuración y secretos',
  'DataStack y seed',
  'ApiStack y Lambda',
  'Reconciliador',
  'Observabilidad y presupuesto',
  'WebStack, S3 y CloudFront',
  'Dominio, TLS, CORS y headers',
  'Pipeline de release',
  'Smoke post-deploy',
  'Validación sandbox',
  'Seguridad real',
  'Rendimiento y accesibilidad focal',
  'Rollback frontend',
  'Rollback API/datos',
  'Re-promoción y smoke final',
  'Repositorio público y README',
  'Release notes',
  'Evidencias y trazabilidad',
  'Scorecard de rúbrica',
  'Riesgos, incidentes y desviaciones',
  'Cleanup y coste residual',
  'Evaluación GATE-E7-01',
  'Evaluación GATE-E7-02',
  'Evaluación GATE-E7-03',
  'Handoff a etapa 8',
];

export class Stage7Error extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7Error';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7Error(code);
};

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, expected) =>
  object(value) && Object.keys(value).toSorted().join('\0') === expected.toSorted().join('\0');
const exactArray = (value, allowed, { min = 1, max = allowed.length } = {}) =>
  Array.isArray(value) &&
  value.length >= min &&
  value.length <= max &&
  new Set(value).size === value.length &&
  value.every((entry) => allowed.includes(entry));
const isoUtc = (value) =>
  typeof value === 'string' &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
  !Number.isNaN(Date.parse(value)) &&
  new Date(value).toISOString() === value;
const approvedMoney = (value) => {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return false;
  const cents = value * 100;
  return Number.isSafeInteger(Math.round(cents)) && Math.abs(cents - Math.round(cents)) < 1e-8;
};

const canonicalize = (value) => {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!object(value)) return value;
  return Object.fromEntries(
    Object.keys(value)
      .toSorted()
      .map((key) => [key, canonicalize(value[key])]),
  );
};

export const canonicalJson = (value) => JSON.stringify(canonicalize(value));
export const objectSha256 = (value) => sha256(canonicalJson(value));

const assertAlias = (value, code) => {
  if (typeof value !== 'string' || !ALIAS.test(value)) fail(code);
};

const assertStringArray = (value, pattern, code, { min = 1, max = 8 } = {}) => {
  if (
    !Array.isArray(value) ||
    value.length < min ||
    value.length > max ||
    new Set(value).size !== value.length ||
    !value.every((entry) => typeof entry === 'string' && pattern.test(entry))
  ) {
    fail(code);
  }
};

export const validateStage7Config = (value, { now = new Date() } = {}) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'environment',
      'authorization',
      'aws',
      'window',
      'budget',
      'domain',
      'prereleaseAccess',
      'cleanup',
      'credentialReferences',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.containsSensitiveData !== false ||
    typeof value.environment !== 'string' ||
    !/^(?:assessment-release|assessment-prerelease-[a-z0-9][a-z0-9-]{0,18})$/u.test(
      value.environment,
    ) ||
    `checkout-${value.environment}`.length > 50
  ) {
    fail('E7_CONFIG_ENVELOPE_INVALID');
  }

  const authorization = value.authorization;
  if (
    !exactKeys(authorization, [
      'id',
      'status',
      'scope',
      'ownerAlias',
      'approvedAtUtc',
      'expiresAtUtc',
      'stacks',
      'sandboxIncluded',
      'destructiveActionsAllowed',
      'communicationChannelAlias',
      'abortCriteria',
      'rollbackOwnerAlias',
    ]) ||
    typeof authorization.id !== 'string' ||
    !/^AUTH-E7-[A-Z0-9][A-Z0-9-]{1,31}$/u.test(authorization.id) ||
    authorization.status !== 'APPROVED' ||
    !AUTHORIZATION_SCOPES.includes(authorization.scope) ||
    !isoUtc(authorization.approvedAtUtc) ||
    !isoUtc(authorization.expiresAtUtc) ||
    typeof authorization.sandboxIncluded !== 'boolean' ||
    authorization.destructiveActionsAllowed !== false ||
    !exactArray(authorization.abortCriteria, ABORT_CRITERIA, { min: 7 }) ||
    !REQUIRED_ABORT_CRITERIA.every((criterion) => authorization.abortCriteria.includes(criterion))
  ) {
    fail('E7_AUTHORIZATION_INVALID');
  }
  assertAlias(authorization.ownerAlias, 'E7_AUTHORIZATION_OWNER_INVALID');
  assertAlias(authorization.communicationChannelAlias, 'E7_AUTHORIZATION_CHANNEL_INVALID');
  assertAlias(authorization.rollbackOwnerAlias, 'E7_ROLLBACK_OWNER_INVALID');
  assertStringArray(authorization.stacks, STACK, 'E7_STACK_SCOPE_INVALID');
  if (authorization.stacks.join('\0') !== expectedStage7Stacks(value.environment).join('\0')) {
    fail('E7_STACK_SCOPE_INVALID');
  }

  const aws = value.aws;
  if (
    !exactKeys(aws, ['accountId', 'region', 'roles', 'sessionMode']) ||
    typeof aws.accountId !== 'string' ||
    !/^[0-9]{12}$/u.test(aws.accountId) ||
    typeof aws.region !== 'string' ||
    !AWS_REGION.test(aws.region) ||
    !exactKeys(aws.roles, [
      'readRoleArn',
      'deployRoleArn',
      'rollbackRoleArn',
      'cleanupRoleArn',
      'baselineRoleArn',
    ]) ||
    !['OIDC', 'TEMPORARY_SESSION'].includes(aws.sessionMode)
  ) {
    fail('E7_AWS_TARGET_INVALID');
  }
  for (const roleArn of Object.values(aws.roles)) {
    const roleMatch = /^arn:aws:iam::([0-9]{12}):role\/([A-Za-z0-9+=,.@_/-]{1,256})$/u.exec(
      roleArn,
    );
    if (
      roleMatch === null ||
      roleMatch[1] !== aws.accountId ||
      /(?:^|[/_-])admin(?:istrator)?(?:$|[/_-])/iu.test(roleMatch[2])
    ) {
      fail('E7_DEPLOY_ROLE_INVALID');
    }
  }
  if (new Set(Object.values(aws.roles)).size !== 5) fail('E7_AWS_ROLE_SEPARATION_INVALID');

  const window = value.window;
  if (
    !exactKeys(window, ['startsAtUtc', 'endsAtUtc']) ||
    !isoUtc(window.startsAtUtc) ||
    !isoUtc(window.endsAtUtc)
  ) {
    fail('E7_RELEASE_WINDOW_INVALID');
  }
  const approvedAt = Date.parse(authorization.approvedAtUtc);
  const authorizationExpiresAt = Date.parse(authorization.expiresAtUtc);
  const startsAt = Date.parse(window.startsAtUtc);
  const endsAt = Date.parse(window.endsAtUtc);
  const nowTime = now instanceof Date ? now.getTime() : Number.NaN;
  if (
    !Number.isFinite(nowTime) ||
    approvedAt > nowTime ||
    authorizationExpiresAt <= nowTime ||
    startsAt < approvedAt ||
    endsAt <= startsAt ||
    endsAt > authorizationExpiresAt ||
    endsAt - startsAt > 24 * 60 * 60 * 1000
  ) {
    fail('E7_RELEASE_WINDOW_NOT_AUTHORIZED');
  }

  const budget = value.budget;
  if (
    !exactKeys(budget, [
      'maxUsd',
      'warningUsd',
      'alertOwnerAlias',
      'alertChannelAlias',
      'alertDestinationSha256',
    ]) ||
    !approvedMoney(budget.maxUsd) ||
    !SHA256.test(budget.alertDestinationSha256 ?? '') ||
    !Array.isArray(budget.warningUsd) ||
    budget.warningUsd.length < 1 ||
    budget.warningUsd.length > 3 ||
    !budget.warningUsd.every(
      (threshold, index) =>
        approvedMoney(threshold) &&
        threshold < budget.maxUsd &&
        (index === 0 || threshold > budget.warningUsd[index - 1]),
    )
  ) {
    fail('E7_BUDGET_INVALID');
  }
  assertAlias(budget.alertOwnerAlias, 'E7_BUDGET_OWNER_INVALID');
  assertAlias(budget.alertChannelAlias, 'E7_BUDGET_CHANNEL_INVALID');

  const domain = value.domain;
  if (
    !exactKeys(domain, [
      'mode',
      'hostname',
      'apiHostname',
      'hostedZoneId',
      'webCertificateArn',
      'apiCertificateArn',
      'dnsIncluded',
    ]) ||
    !['AWS_MANAGED', 'CUSTOM_AUTHORIZED'].includes(domain.mode) ||
    typeof domain.dnsIncluded !== 'boolean' ||
    !(
      (domain.mode === 'AWS_MANAGED' &&
        domain.hostname === null &&
        domain.apiHostname === null &&
        domain.hostedZoneId === null &&
        domain.webCertificateArn === null &&
        domain.apiCertificateArn === null &&
        !domain.dnsIncluded) ||
      (domain.mode === 'CUSTOM_AUTHORIZED' &&
        typeof domain.hostname === 'string' &&
        HOSTNAME.test(domain.hostname) &&
        typeof domain.apiHostname === 'string' &&
        HOSTNAME.test(domain.apiHostname) &&
        domain.hostname !== domain.apiHostname &&
        domain.hostname.split('.').slice(1).join('.') ===
          domain.apiHostname.split('.').slice(1).join('.') &&
        typeof domain.hostedZoneId === 'string' &&
        HOSTED_ZONE_ID.test(domain.hostedZoneId) &&
        domain.webCertificateArn ===
          `arn:aws:acm:us-east-1:${aws.accountId}:certificate/${domain.webCertificateArn?.split('/').at(-1)}` &&
        /^arn:aws:acm:us-east-1:[0-9]{12}:certificate\/[0-9a-f-]{36}$/u.test(
          domain.webCertificateArn,
        ) &&
        domain.apiCertificateArn ===
          `arn:aws:acm:${aws.region}:${aws.accountId}:certificate/${domain.apiCertificateArn?.split('/').at(-1)}` &&
        new RegExp(`^arn:aws:acm:${aws.region}:[0-9]{12}:certificate/[0-9a-f-]{36}$`, 'u').test(
          domain.apiCertificateArn,
        ) &&
        domain.dnsIncluded)
    )
  ) {
    fail('E7_DOMAIN_STRATEGY_INVALID');
  }

  const cleanup = value.cleanup;
  if (
    !exactKeys(cleanup, [
      'ownerAlias',
      'expiresAtUtc',
      'preserveBootstrap',
      'preservePreviousRelease',
    ]) ||
    !isoUtc(cleanup.expiresAtUtc) ||
    Date.parse(cleanup.expiresAtUtc) <= endsAt ||
    cleanup.preserveBootstrap !== true ||
    cleanup.preservePreviousRelease !== true
  ) {
    fail('E7_CLEANUP_PLAN_INVALID');
  }
  if (
    authorization.scope === 'EPHEMERAL_PRERELEASE' &&
    Date.parse(cleanup.expiresAtUtc) > authorizationExpiresAt - 2 * 60 * 60 * 1000
  ) {
    fail('E7_CLEANUP_AUTHORIZATION_WINDOW_INVALID');
  }
  assertAlias(cleanup.ownerAlias, 'E7_CLEANUP_OWNER_INVALID');

  assertStringArray(
    value.credentialReferences,
    CREDENTIAL_REFERENCE,
    'E7_CREDENTIAL_REFERENCES_INVALID',
    { min: 0, max: 6 },
  );
  for (const reference of value.credentialReferences) {
    const parts = reference.split(':');
    if (parts[3] !== aws.region || parts[4] !== aws.accountId) {
      fail('E7_CREDENTIAL_REFERENCE_TARGET_MISMATCH');
    }
  }
  const prereleaseAccess = value.prereleaseAccess;
  if (
    !exactKeys(prereleaseAccess, [
      'mode',
      'keyGroupId',
      'publicKeyId',
      'originTokenSecretArn',
      'originTokenSecretVersionId',
      'rotationDuringWindow',
    ]) ||
    !(
      (authorization.scope === 'EPHEMERAL_PRERELEASE' &&
        prereleaseAccess.mode === 'CLOUDFRONT_SIGNED_COOKIE' &&
        typeof prereleaseAccess.keyGroupId === 'string' &&
        /^[A-Z0-9]{8,64}$/u.test(prereleaseAccess.keyGroupId) &&
        typeof prereleaseAccess.publicKeyId === 'string' &&
        /^[A-Z0-9]{8,64}$/u.test(prereleaseAccess.publicKeyId) &&
        typeof prereleaseAccess.originTokenSecretArn === 'string' &&
        /^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,256}$/u.test(
          prereleaseAccess.originTokenSecretArn,
        ) &&
        /^[A-Za-z0-9-]{32,64}$/u.test(prereleaseAccess.originTokenSecretVersionId ?? '') &&
        prereleaseAccess.rotationDuringWindow === 'FORBIDDEN' &&
        value.credentialReferences.includes(prereleaseAccess.originTokenSecretArn)) ||
      (authorization.scope === 'FULL_RELEASE_VERSIONED_UPDATE' &&
        prereleaseAccess.mode === 'ORIGIN_GATE_ONLY' &&
        prereleaseAccess.keyGroupId === null &&
        prereleaseAccess.publicKeyId === null &&
        typeof prereleaseAccess.originTokenSecretArn === 'string' &&
        /^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,256}$/u.test(
          prereleaseAccess.originTokenSecretArn,
        ) &&
        /^[A-Za-z0-9-]{32,64}$/u.test(prereleaseAccess.originTokenSecretVersionId ?? '') &&
        prereleaseAccess.rotationDuringWindow === 'FORBIDDEN' &&
        value.credentialReferences.includes(prereleaseAccess.originTokenSecretArn)) ||
      (authorization.scope === 'NON_MUTATING_PLAN' &&
        prereleaseAccess.mode === 'NOT_APPLICABLE' &&
        prereleaseAccess.keyGroupId === null &&
        prereleaseAccess.publicKeyId === null &&
        prereleaseAccess.originTokenSecretArn === null &&
        prereleaseAccess.originTokenSecretVersionId === null &&
        prereleaseAccess.rotationDuringWindow === 'NOT_APPLICABLE')
    )
  ) {
    fail('E7_PRERELEASE_ACCESS_CONFIGURATION_INVALID');
  }
  if (
    authorization.scope === 'FULL_RELEASE_VERSIONED_UPDATE' &&
    (value.environment !== 'assessment-release' ||
      !authorization.sandboxIncluded ||
      value.credentialReferences.length === 0 ||
      value.domain.mode !== 'CUSTOM_AUTHORIZED')
  ) {
    fail('E7_FULL_RELEASE_AUTHORIZATION_INCOMPLETE');
  }
  if (
    authorization.scope === 'EPHEMERAL_PRERELEASE' &&
    (!value.environment.startsWith('assessment-prerelease-') ||
      !authorization.sandboxIncluded ||
      value.credentialReferences.length === 0)
  ) {
    fail('E7_PRERELEASE_AUTHORIZATION_INCOMPLETE');
  }

  return value;
};

export const stage7ConfigSummary = (config) => ({
  schemaVersion: 1,
  stage: 7,
  authorizationId: config.authorization.id,
  authorizationScope: config.authorization.scope,
  environment: config.environment,
  accountSha256: sha256(config.aws.accountId),
  accountSuffix: config.aws.accountId.slice(-4),
  region: config.aws.region,
  roleSha256: Object.fromEntries(
    Object.entries(config.aws.roles).map(([name, roleArn]) => [name, sha256(roleArn)]),
  ),
  sessionMode: config.aws.sessionMode,
  window: config.window,
  budget: config.budget,
  domain: config.domain,
  cleanup: config.cleanup,
  credentialReferenceSha256: config.credentialReferences.map(sha256),
  containsSensitiveData: false,
});

const FULL_EXTERNAL_AUTHORIZATION_IDS = ['AUTH-E7-EXT-01', 'AUTH-E7-EXT-02', 'AUTH-E7-EXT-03'];

export const validateStage7AuthorizationUsage = (
  value,
  { usageId, candidateSha, releaseId, configSha256 },
) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'usageId',
      'bundleSha256',
      'candidateSha',
      'releaseId',
      'configSha256',
      'ownedOriginSha256',
      'sandboxHostSha256',
      'requestCounts',
    ]) ||
    value.schemaVersion !== 1 ||
    value.usageId !== usageId ||
    value.candidateSha !== candidateSha ||
    value.releaseId !== releaseId ||
    value.configSha256 !== configSha256 ||
    !SHA256.test(value.bundleSha256 ?? '') ||
    !SHA256.test(value.ownedOriginSha256 ?? '') ||
    !SHA256.test(value.sandboxHostSha256 ?? '') ||
    !exactKeys(value.requestCounts, FULL_EXTERNAL_AUTHORIZATION_IDS) ||
    Object.values(value.requestCounts).some((count) => !Number.isSafeInteger(count) || count < 0)
  ) {
    fail('E7_AUTHORIZATION_USAGE_CONTRACT_INVALID');
  }
  return value;
};

const publicationStackState = (value, stackName, state, code) => {
  if (
    !exactKeys(value, ['stackName', 'stackIdSha256', 'state']) ||
    value.stackName !== stackName ||
    value.state !== state ||
    !SHA256.test(value.stackIdSha256 ?? '')
  ) {
    fail(code);
  }
  return value;
};

const publicationStackTransition = (value, stackName, previousState, state, code) => {
  if (
    !exactKeys(value, ['changed', 'previousState', 'state', 'stackIdSha256', 'stackName']) ||
    value.changed !== true ||
    value.previousState !== previousState ||
    value.state !== state ||
    value.stackName !== stackName ||
    !SHA256.test(value.stackIdSha256 ?? '')
  ) {
    fail(code);
  }
  return value;
};

const publicationSchedulerState = (value, stackName, state, code) => {
  if (
    !exactKeys(value, ['controlledBy', 'stackName', 'state']) ||
    value.controlledBy !== 'PublicationState' ||
    value.stackName !== stackName ||
    value.state !== state
  ) {
    fail(code);
  }
  return value;
};

export const validateStage7ActivationCheckpoint = (
  value,
  { config, candidateSha, releaseId, manifestSha256, complete = false },
) => {
  const configSha256 = objectSha256(config);
  const [dataStack, apiStack, observabilityStack, webStack] = expectedStage7Stacks(
    config.environment,
  );
  void dataStack;
  void observabilityStack;
  if (
    !exactKeys(value, [
      'decision',
      'releaseMode',
      'updateReleaseSupported',
      'previousReleaseManifestSha256',
      'assemblySha256',
      'freezeManifestSha256',
      'seedEvidenceSha256',
      'publicOriginSha256',
      'externalAuthorization',
      'observabilityReadiness',
      'publication',
      'promotions',
      'scheduleTargetSha256',
      'transitions',
    ]) ||
    value.decision !== 'ACTIVATED_REQUIRES_SMOKE' ||
    value.releaseMode !== 'VERSIONED_UPDATE' ||
    value.updateReleaseSupported !== true ||
    !SHA256.test(value.previousReleaseManifestSha256 ?? '') ||
    !SHA256.test(value.assemblySha256 ?? '') ||
    value.freezeManifestSha256 !== manifestSha256 ||
    !SHA256.test(value.seedEvidenceSha256 ?? '') ||
    !SHA256.test(value.publicOriginSha256 ?? '') ||
    !SHA256.test(value.scheduleTargetSha256 ?? '') ||
    !exactKeys(value.externalAuthorization, [
      'authorizationSha256',
      'authorizationIds',
      'publicOriginSha256',
    ]) ||
    !SHA256.test(value.externalAuthorization.authorizationSha256 ?? '') ||
    value.externalAuthorization.authorizationIds?.join('\0') !==
      FULL_EXTERNAL_AUTHORIZATION_IDS.join('\0') ||
    value.externalAuthorization.publicOriginSha256 !== value.publicOriginSha256 ||
    !exactKeys(value.observabilityReadiness, [
      'evidenceSha256',
      'alertDestinationSha256',
      'alertTopicSha256',
      'status',
    ]) ||
    !SHA256.test(value.observabilityReadiness.evidenceSha256 ?? '') ||
    value.observabilityReadiness.alertDestinationSha256 !== config.budget.alertDestinationSha256 ||
    !SHA256.test(value.observabilityReadiness.alertTopicSha256 ?? '') ||
    value.observabilityReadiness.status !== 'CONFIRMED' ||
    !exactKeys(value.publication, [
      'managedByCloudFormation',
      'apiStack',
      'webStack',
      'scheduler',
    ]) ||
    value.publication.managedByCloudFormation !== true ||
    !exactKeys(value.promotions, ['api', 'worker', 'web']) ||
    !exactKeys(value.promotions.api, ['changed', 'version']) ||
    value.promotions.api.changed !== false ||
    !/^[1-9][0-9]*$/u.test(value.promotions.api.version ?? '') ||
    !exactKeys(value.promotions.worker, ['changed', 'version']) ||
    value.promotions.worker.changed !== false ||
    !/^[1-9][0-9]*$/u.test(value.promotions.worker.version ?? '') ||
    !exactKeys(value.promotions.web, ['invalidatedPaths', 'restoredObjects']) ||
    !Array.isArray(value.promotions.web.invalidatedPaths) ||
    value.promotions.web.invalidatedPaths.length !== 0 ||
    value.promotions.web.restoredObjects !== 0 ||
    !Array.isArray(value.transitions) ||
    value.transitions.length < 1 ||
    value.transitions.length > 2 ||
    (complete && value.transitions.length !== 2)
  ) {
    fail('E7_ACTIVATION_CHECKPOINT_INVALID');
  }
  publicationStackState(
    value.publication.apiStack,
    apiStack,
    'ENABLED',
    'E7_ACTIVATION_PUBLICATION_INVALID',
  );
  publicationStackState(
    value.publication.webStack,
    webStack,
    'ENABLED',
    'E7_ACTIVATION_PUBLICATION_INVALID',
  );
  publicationSchedulerState(
    value.publication.scheduler,
    apiStack,
    'ENABLED',
    'E7_ACTIVATION_PUBLICATION_INVALID',
  );
  const expectedModes = ['CANDIDATE_ACTIVATION', 'REPROMOTION'];
  for (const [index, transition] of value.transitions.entries()) {
    if (
      !exactKeys(transition, [
        'sequence',
        'mode',
        'apiStack',
        'webStack',
        'scheduler',
        'authorizationUsage',
      ]) ||
      transition.sequence !== index + 1 ||
      transition.mode !== expectedModes[index]
    ) {
      fail('E7_ACTIVATION_TRANSITION_INVALID');
    }
    publicationStackTransition(
      transition.apiStack,
      apiStack,
      'DISABLED',
      'ENABLED',
      'E7_ACTIVATION_TRANSITION_INVALID',
    );
    publicationStackTransition(
      transition.webStack,
      webStack,
      'DISABLED',
      'ENABLED',
      'E7_ACTIVATION_TRANSITION_INVALID',
    );
    publicationSchedulerState(
      transition.scheduler,
      apiStack,
      'ENABLED',
      'E7_ACTIVATION_TRANSITION_INVALID',
    );
    validateStage7AuthorizationUsage(transition.authorizationUsage, {
      usageId: index === 0 ? 'ACTIVATION_CANDIDATE' : 'ACTIVATION_REPROMOTION',
      candidateSha,
      releaseId,
      configSha256,
    });
  }
  const finalTransition = value.transitions.at(-1);
  if (
    value.publication.apiStack.stackName !== finalTransition.apiStack.stackName ||
    value.publication.apiStack.stackIdSha256 !== finalTransition.apiStack.stackIdSha256 ||
    value.publication.apiStack.state !== finalTransition.apiStack.state ||
    value.publication.webStack.stackName !== finalTransition.webStack.stackName ||
    value.publication.webStack.stackIdSha256 !== finalTransition.webStack.stackIdSha256 ||
    value.publication.webStack.state !== finalTransition.webStack.state ||
    value.publication.scheduler.stackName !== finalTransition.scheduler.stackName ||
    value.publication.scheduler.state !== finalTransition.scheduler.state
  ) {
    fail('E7_ACTIVATION_FINAL_TRANSITION_MISMATCH');
  }
  return value;
};

export const validateStage7InitialRollbackCheckpoint = (value, { config }) => {
  const [, apiStack, , webStack] = expectedStage7Stacks(config.environment);
  if (
    !exactKeys(value, [
      'decision',
      'releaseMode',
      'updateReleaseSupported',
      'publication',
      'aliasesChanged',
      'objectsChanged',
      'dataFactsChanged',
      'stacksDeleted',
      'secretDeleted',
    ]) ||
    value.decision !== 'INITIAL_RELEASE_DISABLED_AND_UNPUBLISHED_REQUIRES_SMOKE' ||
    value.releaseMode !== 'INITIAL' ||
    value.updateReleaseSupported !== false ||
    !exactKeys(value.publication, [
      'managedByCloudFormation',
      'apiStack',
      'webStack',
      'scheduler',
    ]) ||
    value.publication.managedByCloudFormation !== true ||
    value.aliasesChanged !== false ||
    value.objectsChanged !== false ||
    value.dataFactsChanged !== false ||
    value.stacksDeleted !== 0 ||
    value.secretDeleted !== false
  ) {
    fail('E7_INITIAL_ROLLBACK_CHECKPOINT_INVALID');
  }
  publicationStackTransition(
    value.publication.apiStack,
    apiStack,
    'ENABLED',
    'DISABLED',
    'E7_INITIAL_ROLLBACK_PUBLICATION_INVALID',
  );
  publicationStackTransition(
    value.publication.webStack,
    webStack,
    'ENABLED',
    'DISABLED',
    'E7_INITIAL_ROLLBACK_PUBLICATION_INVALID',
  );
  publicationSchedulerState(
    value.publication.scheduler,
    apiStack,
    'DISABLED',
    'E7_INITIAL_ROLLBACK_PUBLICATION_INVALID',
  );
  return value;
};

export const validateStage7DriftCheckpoint = (
  value,
  { config, manifestSha256, assemblySha256 },
) => {
  if (
    !exactKeys(value, [
      'decision',
      'releaseMode',
      'updateReleaseSupported',
      'previousReleaseManifestSha256',
      'assemblySha256',
      'freezeManifestSha256',
      'publicationManagedByCloudFormation',
      'checked',
      'criticalCount',
      'stacks',
    ]) ||
    value.decision !== 'PASS' ||
    value.releaseMode !== 'VERSIONED_UPDATE' ||
    value.updateReleaseSupported !== true ||
    !SHA256.test(value.previousReleaseManifestSha256 ?? '') ||
    value.assemblySha256 !== assemblySha256 ||
    value.freezeManifestSha256 !== manifestSha256 ||
    value.publicationManagedByCloudFormation !== true ||
    value.checked !== 4 ||
    value.criticalCount !== 0 ||
    !Array.isArray(value.stacks) ||
    value.stacks.length !== 4
  ) {
    fail('E7_DRIFT_CHECKPOINT_INVALID');
  }
  for (const [index, stack] of value.stacks.entries()) {
    if (
      !exactKeys(stack, [
        'detectionIdSha256',
        'driftedResourceCount',
        'stackIdSha256',
        'stackName',
        'status',
      ]) ||
      !SHA256.test(stack.detectionIdSha256 ?? '') ||
      stack.driftedResourceCount !== 0 ||
      !SHA256.test(stack.stackIdSha256 ?? '') ||
      stack.stackName !== config.authorization.stacks[index] ||
      stack.status !== 'IN_SYNC'
    ) {
      fail('E7_DRIFT_STACK_INVALID');
    }
  }
  return value;
};

export const validateStage7PrereleaseCleanupCheckpoint = (
  value,
  { config, assemblySha256, enforceExpiry = false },
) => {
  const expectedDestructionOrder = [...expectedStage7Stacks(config.environment)].reverse();
  const expectedConfirmationSha256 = sha256(
    [
      config.authorization.id,
      config.environment,
      config.cleanup.expiresAtUtc,
      'DESTROY_EPHEMERAL_STACKS',
    ].join('\0'),
  );
  if (
    config.authorization.scope !== 'EPHEMERAL_PRERELEASE' ||
    !exactKeys(value, [
      'decision',
      'identity',
      'assemblySha256',
      'confirmationSha256',
      'enforceExpiry',
      'destroyedStacks',
      'destructionOrder',
      'bootstrapPreserved',
      'previousReleasePreserved',
      'retainedDataDeleted',
      'residual',
    ]) ||
    value.decision !== 'PASS' ||
    !exactKeys(value.identity, [
      'accountSha256',
      'accountSuffix',
      'roleSha256',
      'sessionArnSha256',
    ]) ||
    value.identity.accountSha256 !== sha256(config.aws.accountId) ||
    value.identity.accountSuffix !== config.aws.accountId.slice(-4) ||
    value.identity.roleSha256 !== sha256(config.aws.roles.cleanupRoleArn) ||
    !SHA256.test(value.identity.sessionArnSha256 ?? '') ||
    value.assemblySha256 !== assemblySha256 ||
    value.confirmationSha256 !== expectedConfirmationSha256 ||
    value.enforceExpiry !== enforceExpiry ||
    value.destroyedStacks?.join('\0') !== expectedDestructionOrder.join('\0') ||
    value.destructionOrder?.join('\0') !== expectedDestructionOrder.join('\0') ||
    value.bootstrapPreserved !== true ||
    value.previousReleasePreserved !== true ||
    value.retainedDataDeleted !== false ||
    !exactKeys(value.residual, ['count', 'preservedExternalReferences', 'resourceTypeHashes']) ||
    value.residual.count !== 0 ||
    !Number.isSafeInteger(value.residual.preservedExternalReferences) ||
    value.residual.preservedExternalReferences < 0 ||
    !Array.isArray(value.residual.resourceTypeHashes) ||
    value.residual.resourceTypeHashes.length !== 0
  ) {
    fail('E7_PRERELEASE_CLEANUP_CHECKPOINT_INVALID');
  }
  return value;
};

export const readStrictJsonFile = (
  filename,
  { scanForbiddenData = true, now = new Date(), validateConfig = false } = {},
) => {
  const parsed = parseStrictJsonSource(readFileSync(path.resolve(filename)), {
    scanForbiddenData: validateConfig ? false : scanForbiddenData,
  });
  return validateConfig ? validateStage7Config(parsed, { now }) : parsed;
};

const expectedIds = (prefix, total) =>
  Array.from({ length: total }, (_, index) => `${prefix}-${String(index + 1).padStart(2, '0')}`);
const sameIds = (actual, expected) =>
  Array.isArray(actual) &&
  actual.length === expected.length &&
  new Set(actual).size === actual.length &&
  actual.toSorted().join('\0') === expected.toSorted().join('\0');

export const assessStage6Manifest = (manifest) => {
  const candidate = manifest?.candidate;
  const gates = manifest?.gates;
  const validEnvelope =
    manifest?.schemaVersion === 1 &&
    manifest?.stage === 6 &&
    manifest?.artifactId === 'ART-VER-16' &&
    manifest?.dataClassification === 'C0_SANITIZED_SUMMARY' &&
    manifest?.containsSensitiveData === false &&
    manifest?.requiredDocumentsValid === true &&
    manifest?.externalRequestsMadeByCloseout === 0 &&
    typeof manifest?.runId === 'string' &&
    RUN_ID.test(manifest.runId) &&
    object(candidate) &&
    SHA.test(candidate.commitSha ?? '') &&
    SHA.test(candidate.treeSha ?? '') &&
    candidate.workingTree === 'CLEAN' &&
    candidate.changedFiles === 0 &&
    exactKeys(gates, ['GATE-E6-01', 'GATE-E6-02', 'GATE-E6-03']) &&
    manifest?.artifactSummary?.total === 18 &&
    manifest?.artifactSummary?.failed === 0 &&
    manifest?.evidenceSummary?.total === 40 &&
    sameIds(
      manifest?.artifacts?.map((entry) => entry?.id),
      expectedIds('ART-VER', 18),
    ) &&
    sameIds(
      manifest?.evidence?.map((entry) => entry?.id),
      expectedIds('EVD-E6', 40),
    );
  if (!validEnvelope) {
    return { status: 'FAIL', code: 'E6_MANIFEST_CONTRACT_INVALID' };
  }
  if (
    gates['GATE-E6-01'] === 'PASS' &&
    gates['GATE-E6-02'] === 'PASS' &&
    gates['GATE-E6-03'] === 'PASS' &&
    manifest.status === 'RELEASE_CANDIDATE' &&
    manifest.releasePolicy === 'STAGE_7_FULL_ENABLED' &&
    manifest.evidenceSummary.pass === 40 &&
    manifest.evidenceSummary.notRunAuth === 0 &&
    manifest.evidenceSummary.blocked === 0
  ) {
    return { status: 'PASS', code: 'E6_RELEASE_CANDIDATE', candidate, runId: manifest.runId };
  }
  if (
    gates['GATE-E6-01'] === 'PASS' &&
    ['PASS', 'CONDITIONAL_GO'].includes(gates['GATE-E6-02']) &&
    gates['GATE-E6-03'] === 'CONDITIONAL_GO' &&
    manifest.status === 'CONDITIONAL_GO_NOT_PUBLIC_RELEASE' &&
    manifest.releasePolicy === 'STAGE_7_NON_PUBLIC_PRERELEASE_ONLY'
  ) {
    return {
      status: 'CONDITIONAL_GO',
      code: 'E6_NON_PUBLIC_PRERELEASE_ONLY',
      candidate,
      runId: manifest.runId,
    };
  }
  return { status: 'FAIL', code: 'E6_GATE_OR_POLICY_INVALID', candidate, runId: manifest.runId };
};

const git = (arguments_) => {
  try {
    return execFileSync('git', arguments_, {
      cwd: workspaceRoot,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
      windowsHide: true,
    }).trim();
  } catch {
    fail('E7_GIT_COMMAND_FAILED');
  }
};

export const currentCandidate = () => {
  const commitSha = git(['rev-parse', 'HEAD']);
  const changed = git(['status', '--porcelain=v1', '-z']);
  const changedFiles = changed.length === 0 ? 0 : changed.split('\0').filter(Boolean).length;
  return {
    commitSha,
    treeSha: git(['rev-parse', 'HEAD^{tree}']),
    branch: stage6Branch({
      gitBranch: git(['branch', '--show-current']),
      commitSha,
    }),
    workingTree: changedFiles === 0 ? 'CLEAN' : 'DIRTY',
    changedFiles,
  };
};

const containedPath = (candidatePath, rootDirectory) => {
  const root = realpathSync(rootDirectory);
  if (lstatSync(candidatePath).isSymbolicLink()) fail('E7_ARTIFACT_SYMLINK_REJECTED');
  const resolved = realpathSync(candidatePath);
  const relative = path.relative(root, resolved);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail('E7_ARTIFACT_PATH_OUTSIDE_ROOT');
  }
  return { resolved, relative: relative.replaceAll('\\', '/') };
};

const filesUnder = (directory, prefix = '') => {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true }).toSorted((a, b) =>
    a.name === b.name ? 0 : a.name < b.name ? -1 : 1,
  )) {
    if (entry.isSymbolicLink()) fail('E7_ARTIFACT_SYMLINK_REJECTED');
    const absolute = path.join(directory, entry.name);
    const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) files.push(...filesUnder(absolute, relative));
    else if (entry.isFile()) files.push({ absolute, relative });
    else fail('E7_ARTIFACT_SPECIAL_FILE_REJECTED');
  }
  return files;
};

const fileSha256 = (filename) => createHash('sha256').update(readFileSync(filename)).digest('hex');

export const hashArtifactPath = (candidatePath, { rootDirectory = workspaceRoot } = {}) => {
  const { resolved, relative } = containedPath(candidatePath, rootDirectory);
  const stat = lstatSync(resolved);
  if (stat.isSymbolicLink()) fail('E7_ARTIFACT_SYMLINK_REJECTED');
  if (stat.isFile()) {
    return {
      sourcePath: relative,
      kind: 'FILE',
      files: 1,
      bytes: stat.size,
      sha256: fileSha256(resolved),
    };
  }
  if (!stat.isDirectory()) fail('E7_ARTIFACT_PATH_INVALID');
  const files = filesUnder(resolved);
  if (files.length === 0) fail('E7_ARTIFACT_DIRECTORY_EMPTY');
  const digest = createHash('sha256');
  let bytes = 0;
  for (const file of files) {
    const size = lstatSync(file.absolute).size;
    bytes += size;
    digest.update(file.relative);
    digest.update('\0');
    digest.update(fileSha256(file.absolute));
    digest.update('\0');
    digest.update(String(size));
    digest.update('\0');
  }
  return {
    sourcePath: relative,
    kind: 'DIRECTORY',
    files: files.length,
    bytes,
    sha256: digest.digest('hex'),
  };
};

const releaseId = (builtAt, candidateSha) => {
  const date = builtAt.slice(0, 10).replaceAll('-', '');
  const time = builtAt.slice(11, 16).replace(':', '');
  return `rel-${date}-${time}-${candidateSha.slice(0, 7)}`;
};

const freezeBody = (manifest) => {
  const body = { ...manifest };
  delete body.manifestSha256;
  return body;
};

export const validateFreezeManifest = (manifest) => {
  if (
    !exactKeys(manifest, [
      'schemaVersion',
      'stage',
      'kind',
      'releaseId',
      'candidateSha',
      'candidateTreeSha',
      'releaseTag',
      'environment',
      'authorizationScope',
      'region',
      'sourceRunId',
      'sourceArtifactId',
      'sourceArtifactSha256',
      'preFreezeEvidenceSha256',
      'builtAt',
      'configSha256',
      'lockfileSha256',
      'openApiSha256',
      'generatedClientSha256',
      'publicConfigSha256',
      'templateSha256',
      'stage6Gates',
      'toolchain',
      'artifacts',
      'controlInventory',
      'releaseMode',
      'updateReleaseSupported',
      'updateReleaseUnsupportedReason',
      'buildOnce',
      'containsSensitiveData',
      'manifestSha256',
    ]) ||
    manifest.schemaVersion !== 1 ||
    manifest.stage !== 7 ||
    manifest.kind !== 'BUILD_ONCE_FREEZE' ||
    !SHA.test(manifest.candidateSha ?? '') ||
    !SHA.test(manifest.candidateTreeSha ?? '') ||
    !AUTHORIZATION_SCOPES.includes(manifest.authorizationScope) ||
    manifest.authorizationScope === 'NON_MUTATING_PLAN' ||
    typeof manifest.environment !== 'string' ||
    !/^(?:assessment-release|assessment-prerelease-[a-z0-9][a-z0-9-]{0,18})$/u.test(
      manifest.environment,
    ) ||
    `checkout-${manifest.environment}`.length > 50 ||
    !AWS_REGION.test(manifest.region ?? '') ||
    !RUN_ID.test(manifest.sourceRunId ?? '') ||
    !/^[0-9]{1,20}$/u.test(manifest.sourceArtifactId ?? '') ||
    !isoUtc(manifest.builtAt) ||
    manifest.releaseId !== releaseId(manifest.builtAt, manifest.candidateSha) ||
    ![
      manifest.configSha256,
      manifest.lockfileSha256,
      manifest.openApiSha256,
      manifest.generatedClientSha256,
      manifest.publicConfigSha256,
      manifest.templateSha256,
      manifest.sourceArtifactSha256,
      manifest.manifestSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !(
      (manifest.authorizationScope === 'FULL_RELEASE_VERSIONED_UPDATE' &&
        SHA256.test(manifest.preFreezeEvidenceSha256 ?? '')) ||
      (manifest.authorizationScope === 'EPHEMERAL_PRERELEASE' &&
        manifest.preFreezeEvidenceSha256 === null)
    ) ||
    manifest.containsSensitiveData !== false ||
    !(
      (manifest.authorizationScope === 'FULL_RELEASE_VERSIONED_UPDATE' &&
        manifest.releaseMode === 'VERSIONED_UPDATE' &&
        manifest.updateReleaseSupported === true &&
        manifest.updateReleaseUnsupportedReason === null) ||
      (manifest.authorizationScope === 'EPHEMERAL_PRERELEASE' &&
        manifest.releaseMode === 'INITIAL' &&
        manifest.updateReleaseSupported === false &&
        manifest.updateReleaseUnsupportedReason === 'EPHEMERAL_PRERELEASE_INITIAL_ONLY')
    ) ||
    !exactKeys(manifest.controlInventory, ['artifacts', 'evidence', 'audits']) ||
    ![
      [manifest.controlInventory.artifacts, STAGE7_ARTIFACTS],
      [manifest.controlInventory.evidence, STAGE7_EVIDENCE],
      [manifest.controlInventory.audits, STAGE7_AUDITS],
    ].every(
      ([entry, expected]) =>
        exactKeys(entry, ['total', 'idsSha256']) &&
        entry.total === expected.length &&
        entry.idsSha256 === objectSha256(expected.map(({ id }) => id)),
    ) ||
    !exactKeys(manifest.buildOnce, ['immutable', 'rebuilt']) ||
    manifest.buildOnce.immutable !== true ||
    manifest.buildOnce.rebuilt !== false ||
    !exactKeys(manifest.stage6Gates, ['GATE-E6-01', 'GATE-E6-02', 'GATE-E6-03']) ||
    !exactKeys(manifest.toolchain, ['node', 'packageManager', 'cdkCli', 'cdkLibrary', 'awsCli']) ||
    !NODE_VERSION.test(manifest.toolchain.node ?? '') ||
    !PACKAGE_MANAGER.test(manifest.toolchain.packageManager ?? '') ||
    !SEMVER.test(manifest.toolchain.cdkCli ?? '') ||
    !SEMVER.test(manifest.toolchain.cdkLibrary ?? '') ||
    !SEMVER.test(manifest.toolchain.awsCli ?? '') ||
    !Array.isArray(manifest.artifacts) ||
    manifest.artifacts.length !== 4 ||
    manifest.artifacts.map(({ name }) => name).join(',') !== 'web,api,worker,iac'
  ) {
    fail('E7_FREEZE_MANIFEST_INVALID');
  }
  const fullRelease = manifest.authorizationScope === 'FULL_RELEASE_VERSIONED_UPDATE';
  const prerelease = manifest.authorizationScope === 'EPHEMERAL_PRERELEASE';
  if (
    (fullRelease &&
      (manifest.environment !== 'assessment-release' ||
        !RELEASE_TAG.test(manifest.releaseTag ?? '') ||
        !Object.values(manifest.stage6Gates).every((status) => status === 'PASS'))) ||
    (prerelease &&
      (!manifest.environment.startsWith('assessment-prerelease-') ||
        manifest.releaseTag !== null ||
        manifest.stage6Gates['GATE-E6-01'] !== 'PASS' ||
        !['PASS', 'CONDITIONAL_GO'].includes(manifest.stage6Gates['GATE-E6-02']) ||
        manifest.stage6Gates['GATE-E6-03'] !== 'CONDITIONAL_GO'))
  ) {
    fail('E7_FREEZE_SCOPE_GATE_INVALID');
  }
  for (const artifact of manifest.artifacts) {
    if (
      !exactKeys(artifact, ['name', 'sourcePath', 'kind', 'files', 'bytes', 'sha256']) ||
      !['FILE', 'DIRECTORY'].includes(artifact.kind) ||
      !Number.isSafeInteger(artifact.files) ||
      artifact.files < 1 ||
      !Number.isSafeInteger(artifact.bytes) ||
      artifact.bytes < 1 ||
      !SHA256.test(artifact.sha256 ?? '') ||
      typeof artifact.sourcePath !== 'string' ||
      artifact.sourcePath.length === 0 ||
      artifact.sourcePath.includes('\\') ||
      path.posix.isAbsolute(artifact.sourcePath) ||
      artifact.sourcePath.split('/').includes('..')
    ) {
      fail('E7_FREEZE_ARTIFACT_INVALID');
    }
  }
  if (
    new Set(manifest.artifacts.map(({ sourcePath }) => sourcePath)).size !== 4 ||
    manifest.templateSha256 !== manifest.artifacts[3].sha256
  ) {
    fail('E7_FREEZE_ARTIFACT_SET_INVALID');
  }
  if (manifest.manifestSha256 !== objectSha256(freezeBody(manifest))) {
    fail('E7_FREEZE_DIGEST_INVALID');
  }
  return manifest;
};

const releaseIdentityContract = (value, code) => {
  if (
    !exactKeys(value, [
      'candidateSha',
      'candidateTreeSha',
      'releaseId',
      'releaseTag',
      'configSha256',
      'freezeManifestSha256',
      'assemblySha256',
    ]) ||
    !SHA.test(value.candidateSha ?? '') ||
    !SHA.test(value.candidateTreeSha ?? '') ||
    !RELEASE_ID.test(value.releaseId ?? '') ||
    !value.releaseId.endsWith(value.candidateSha.slice(0, 7)) ||
    !RELEASE_TAG.test(value.releaseTag ?? '') ||
    ![value.configSha256, value.freezeManifestSha256, value.assemblySha256].every((digest) =>
      SHA256.test(digest ?? ''),
    )
  ) {
    fail(code);
  }
  return value;
};

const lambdaRollbackTarget = (value, code) => {
  if (
    !exactKeys(value, ['functionName', 'aliasName', 'version', 'codeSha256']) ||
    !LAMBDA_FUNCTION_NAME.test(value.functionName ?? '') ||
    !LAMBDA_ALIAS_NAME.test(value.aliasName ?? '') ||
    !LAMBDA_VERSION.test(value.version ?? '') ||
    !SHA256.test(value.codeSha256 ?? '')
  ) {
    fail(code);
  }
  return value;
};

const versionedWebObjects = (value, code) => {
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    value.map(({ key } = {}) => key).join('\0') !== ['index.html', 'public-config.json'].join('\0')
  ) {
    fail(code);
  }
  for (const entry of value) {
    if (
      !exactKeys(entry, ['key', 'versionId', 'etagSha256', 'contentSha256', 'bytes']) ||
      !WEB_OBJECT_KEY.test(entry.key ?? '') ||
      !S3_VERSION_ID.test(entry.versionId ?? '') ||
      !SHA256.test(entry.etagSha256 ?? '') ||
      !SHA256.test(entry.contentSha256 ?? '') ||
      !Number.isSafeInteger(entry.bytes) ||
      entry.bytes < 1
    ) {
      fail(code);
    }
  }
  return value;
};

const webRollbackTarget = (value, code) => {
  if (
    !exactKeys(value, ['bucketName', 'distributionId', 'objects', 'mutableInvalidationPaths']) ||
    !S3_BUCKET.test(value.bucketName ?? '') ||
    !CLOUDFRONT_DISTRIBUTION_ID.test(value.distributionId ?? '') ||
    value.mutableInvalidationPaths?.join('\0') !== ['/index.html', '/public-config.json'].join('\0')
  ) {
    fail(code);
  }
  versionedWebObjects(value.objects, code);
  return value;
};

const previousReleaseManifestBody = (manifest) => {
  const body = { ...manifest };
  delete body.manifestSha256;
  return body;
};

/**
 * Immutable recovery input for a real N -> N-1 -> N release rehearsal.
 * This artifact deliberately contains no AWS credentials, object bodies or
 * business identifiers: only release identities, resource coordinates and
 * cryptographic evidence bindings.
 */
export const validateStage7PreviousReleaseManifest = (manifest) => {
  if (
    !exactKeys(manifest, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'capturedAtUtc',
      'approvedAtUtc',
      'environment',
      'region',
      'previous',
      'target',
      'resources',
      'compatibility',
      'handoff',
      'approval',
      'containsSensitiveData',
      'manifestSha256',
    ]) ||
    manifest.schemaVersion !== 1 ||
    manifest.stage !== 7 ||
    manifest.kind !== 'PREVIOUS_APPROVED_RELEASE' ||
    manifest.status !== 'APPROVED_IMMUTABLE' ||
    !isoUtc(manifest.capturedAtUtc) ||
    !isoUtc(manifest.approvedAtUtc) ||
    Date.parse(manifest.approvedAtUtc) > Date.parse(manifest.capturedAtUtc) ||
    manifest.environment !== 'assessment-release' ||
    !AWS_REGION.test(manifest.region ?? '') ||
    manifest.containsSensitiveData !== false
  ) {
    fail('E7_PREVIOUS_RELEASE_MANIFEST_INVALID');
  }
  releaseIdentityContract(manifest.previous, 'E7_PREVIOUS_RELEASE_IDENTITY_INVALID');
  releaseIdentityContract(manifest.target, 'E7_PREVIOUS_RELEASE_TARGET_INVALID');
  if (
    manifest.previous.candidateSha === manifest.target.candidateSha ||
    manifest.previous.releaseId === manifest.target.releaseId ||
    manifest.previous.releaseTag === manifest.target.releaseTag ||
    !exactKeys(manifest.resources, ['api', 'worker', 'web'])
  ) {
    fail('E7_PREVIOUS_RELEASE_TARGET_INVALID');
  }
  lambdaRollbackTarget(manifest.resources.api, 'E7_PREVIOUS_RELEASE_API_INVALID');
  lambdaRollbackTarget(manifest.resources.worker, 'E7_PREVIOUS_RELEASE_WORKER_INVALID');
  webRollbackTarget(manifest.resources.web, 'E7_PREVIOUS_RELEASE_WEB_INVALID');
  if (
    !exactKeys(manifest.compatibility, [
      'status',
      'schemaStrategy',
      'dataRollback',
      'apiContractEvidenceSha256',
      'pendingReconciliationEvidenceSha256',
      'smokeEvidenceSha256',
      'smokeVerifiedAtUtc',
    ]) ||
    manifest.compatibility.status !== 'PASS' ||
    manifest.compatibility.schemaStrategy !== 'EXPAND_CONTRACT_N_AND_N_MINUS_1' ||
    manifest.compatibility.dataRollback !== 'FORBIDDEN_FORWARD_ONLY' ||
    ![
      manifest.compatibility.apiContractEvidenceSha256,
      manifest.compatibility.pendingReconciliationEvidenceSha256,
      manifest.compatibility.smokeEvidenceSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !isoUtc(manifest.compatibility.smokeVerifiedAtUtc) ||
    Date.parse(manifest.compatibility.smokeVerifiedAtUtc) > Date.parse(manifest.capturedAtUtc) ||
    !exactKeys(manifest.handoff, [
      'sourceKind',
      'sourceBundleSha256',
      'sourceArtifactProvenanceSha256',
      'targetCompatibilityEvidenceSha256',
      'finalDisableEvidenceSha256',
      'predecessorManifestSha256',
    ]) ||
    !['BASELINE_BOOTSTRAP', 'RELEASE_SUCCESSOR'].includes(manifest.handoff.sourceKind) ||
    ![
      manifest.handoff.sourceBundleSha256,
      manifest.handoff.sourceArtifactProvenanceSha256,
      manifest.handoff.targetCompatibilityEvidenceSha256,
      manifest.handoff.finalDisableEvidenceSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !(
      (manifest.handoff.sourceKind === 'BASELINE_BOOTSTRAP' &&
        manifest.handoff.predecessorManifestSha256 === null) ||
      (manifest.handoff.sourceKind === 'RELEASE_SUCCESSOR' &&
        SHA256.test(manifest.handoff.predecessorManifestSha256 ?? ''))
    ) ||
    !exactKeys(manifest.approval, [
      'status',
      'reviewerAlias',
      'approvalEvidenceSha256',
      'releaseEvidenceSha256',
    ]) ||
    manifest.approval.status !== 'APPROVED' ||
    typeof manifest.approval.reviewerAlias !== 'string' ||
    !ALIAS.test(manifest.approval.reviewerAlias) ||
    !SHA256.test(manifest.approval.approvalEvidenceSha256 ?? '') ||
    !SHA256.test(manifest.approval.releaseEvidenceSha256 ?? '')
  ) {
    fail('E7_PREVIOUS_RELEASE_COMPATIBILITY_INVALID');
  }
  if (manifest.manifestSha256 !== objectSha256(previousReleaseManifestBody(manifest))) {
    fail('E7_PREVIOUS_RELEASE_MANIFEST_DIGEST_INVALID');
  }
  return manifest;
};

export const createStage7PreviousReleaseManifest = (body) => {
  if (!object(body) || Object.hasOwn(body, 'manifestSha256')) {
    fail('E7_PREVIOUS_RELEASE_MANIFEST_INPUT_INVALID');
  }
  return validateStage7PreviousReleaseManifest({
    ...body,
    manifestSha256: objectSha256(body),
  });
};

export const validateStage7PreviousReleaseHandoff = (
  manifest,
  { sourceProvenance, targetCompatibility, finalDisableProvenance },
) => {
  validateStage7PreviousReleaseManifest(manifest);
  if (
    !object(sourceProvenance) ||
    !object(targetCompatibility) ||
    !object(finalDisableProvenance) ||
    objectSha256(sourceProvenance) !== manifest.handoff.sourceArtifactProvenanceSha256 ||
    objectSha256(targetCompatibility) !== manifest.handoff.targetCompatibilityEvidenceSha256 ||
    objectSha256(finalDisableProvenance) !== manifest.handoff.finalDisableEvidenceSha256 ||
    sourceProvenance.bundleSha256 !== manifest.handoff.sourceBundleSha256 ||
    targetCompatibility.baselineBundleSha256 !== manifest.handoff.sourceBundleSha256 ||
    targetCompatibility.sourceArtifactProvenanceSha256 !==
      manifest.handoff.sourceArtifactProvenanceSha256 ||
    targetCompatibility.finalDisableEvidenceSha256 !== manifest.handoff.finalDisableEvidenceSha256
  ) {
    fail('E7_PREVIOUS_RELEASE_HANDOFF_MISMATCH');
  }
  if (
    manifest.handoff.sourceKind === 'BASELINE_BOOTSTRAP' &&
    (sourceProvenance.kind !== 'BASELINE_SOURCE_ARTIFACT_PROVENANCE' ||
      sourceProvenance.status !== 'PASS' ||
      sourceProvenance.headSha !== manifest.previous.candidateSha ||
      targetCompatibility.kind !== 'TARGET_N_MINUS_1_COMPATIBILITY' ||
      targetCompatibility.status !== 'PASS' ||
      targetCompatibility.baselineCandidateSha !== manifest.previous.candidateSha ||
      targetCompatibility.targetCandidateSha !== manifest.target.candidateSha ||
      targetCompatibility.targetReleaseId !== manifest.target.releaseId ||
      targetCompatibility.targetFreezeManifestSha256 !== manifest.target.freezeManifestSha256 ||
      targetCompatibility.baselinePendingEvidenceSha256 !==
        manifest.compatibility.pendingReconciliationEvidenceSha256)
  ) {
    fail('E7_PREVIOUS_RELEASE_BASELINE_HANDOFF_INVALID');
  }
  if (
    manifest.handoff.sourceKind === 'RELEASE_SUCCESSOR' &&
    (sourceProvenance.kind !== 'RELEASE_SUCCESSOR_SOURCE_PROVENANCE' ||
      sourceProvenance.status !== 'PASS' ||
      sourceProvenance.headSha !== manifest.previous.candidateSha ||
      sourceProvenance.predecessorManifestSha256 !== manifest.handoff.predecessorManifestSha256 ||
      targetCompatibility.kind !== 'RELEASE_SUCCESSOR_COMPATIBILITY' ||
      targetCompatibility.status !== 'PASS' ||
      targetCompatibility.previousCandidateSha !== manifest.previous.candidateSha ||
      targetCompatibility.targetCandidateSha !== manifest.target.candidateSha)
  ) {
    fail('E7_PREVIOUS_RELEASE_SUCCESSOR_HANDOFF_INVALID');
  }
  return manifest;
};

export const validateStage7PreviousReleaseForTarget = (manifest, { config, freezeManifest }) => {
  validateStage7PreviousReleaseManifest(manifest);
  validateStage7Config(config, { now: new Date(config.window.startsAtUtc) });
  validateFreezeManifest(freezeManifest);
  const iac = freezeManifest.artifacts.find(({ name }) => name === 'iac');
  if (
    config.authorization.scope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    manifest.environment !== config.environment ||
    manifest.region !== config.aws.region ||
    manifest.target.candidateSha !== freezeManifest.candidateSha ||
    manifest.target.candidateTreeSha !== freezeManifest.candidateTreeSha ||
    manifest.target.releaseId !== freezeManifest.releaseId ||
    manifest.target.releaseTag !== freezeManifest.releaseTag ||
    manifest.target.configSha256 !== objectSha256(config) ||
    manifest.target.freezeManifestSha256 !== freezeManifest.manifestSha256 ||
    manifest.target.assemblySha256 !== iac?.sha256
  ) {
    fail('E7_PREVIOUS_RELEASE_TARGET_MISMATCH');
  }
  return manifest;
};

const candidateRollbackRecordBody = (record) => {
  const body = { ...record };
  delete body.recordSha256;
  return body;
};

export const validateStage7CandidateRollbackRecord = (
  record,
  {
    previousManifest,
    approvalSha256 = record?.approvalSha256,
    planSha256 = record?.planSha256,
    deploymentEvidenceSha256 = record?.deploymentEvidenceSha256,
  } = {},
) => {
  validateStage7PreviousReleaseManifest(previousManifest);
  if (
    !exactKeys(record, [
      'schemaVersion',
      'stage',
      'kind',
      'createdAtUtc',
      'previousReleaseManifestSha256',
      'target',
      'approvalSha256',
      'planSha256',
      'deploymentEvidenceSha256',
      'resources',
      'dataPolicy',
      'containsSensitiveData',
      'recordSha256',
    ]) ||
    record.schemaVersion !== 1 ||
    record.stage !== 7 ||
    record.kind !== 'VERSIONED_ROLLBACK_CANDIDATE' ||
    !isoUtc(record.createdAtUtc) ||
    record.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    canonicalJson(record.target) !== canonicalJson(previousManifest.target) ||
    record.approvalSha256 !== approvalSha256 ||
    record.planSha256 !== planSha256 ||
    record.deploymentEvidenceSha256 !== deploymentEvidenceSha256 ||
    ![record.approvalSha256, record.planSha256, record.deploymentEvidenceSha256].every((digest) =>
      SHA256.test(digest ?? ''),
    ) ||
    !exactKeys(record.resources, ['api', 'worker', 'web']) ||
    record.dataPolicy !== 'NO_ROLLBACK_FORWARD_ONLY' ||
    record.containsSensitiveData !== false
  ) {
    fail('E7_CANDIDATE_ROLLBACK_RECORD_INVALID');
  }
  lambdaRollbackTarget(record.resources.api, 'E7_CANDIDATE_ROLLBACK_API_INVALID');
  lambdaRollbackTarget(record.resources.worker, 'E7_CANDIDATE_ROLLBACK_WORKER_INVALID');
  webRollbackTarget(record.resources.web, 'E7_CANDIDATE_ROLLBACK_WEB_INVALID');
  const previous = previousManifest.resources;
  const previousKeys = previous.web.objects.map(({ key }) => key).join('\0');
  const candidateKeys = record.resources.web.objects.map(({ key }) => key).join('\0');
  const candidateByKey = new Map(record.resources.web.objects.map((entry) => [entry.key, entry]));
  if (
    record.resources.api.functionName !== previous.api.functionName ||
    record.resources.api.aliasName !== previous.api.aliasName ||
    record.resources.api.version === previous.api.version ||
    record.resources.worker.functionName !== previous.worker.functionName ||
    record.resources.worker.aliasName !== previous.worker.aliasName ||
    record.resources.worker.version === previous.worker.version ||
    record.resources.web.bucketName !== previous.web.bucketName ||
    record.resources.web.distributionId !== previous.web.distributionId ||
    previousKeys !== candidateKeys ||
    ['index.html', 'public-config.json'].some(
      (key) =>
        candidateByKey.get(key)?.versionId ===
          previous.web.objects.find((entry) => entry.key === key)?.versionId ||
        candidateByKey.get(key)?.contentSha256 ===
          previous.web.objects.find((entry) => entry.key === key)?.contentSha256,
    )
  ) {
    fail('E7_CANDIDATE_ROLLBACK_TARGET_MISMATCH');
  }
  if (record.recordSha256 !== objectSha256(candidateRollbackRecordBody(record))) {
    fail('E7_CANDIDATE_ROLLBACK_RECORD_DIGEST_INVALID');
  }
  return record;
};

export const createStage7CandidateRollbackRecord = ({
  previousManifest,
  createdAtUtc,
  approvalSha256,
  planSha256,
  deploymentEvidenceSha256,
  resources,
}) => {
  validateStage7PreviousReleaseManifest(previousManifest);
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_CANDIDATE',
    createdAtUtc,
    previousReleaseManifestSha256: previousManifest.manifestSha256,
    target: { ...previousManifest.target },
    approvalSha256,
    planSha256,
    deploymentEvidenceSha256,
    resources,
    dataPolicy: 'NO_ROLLBACK_FORWARD_ONLY',
    containsSensitiveData: false,
  };
  return validateStage7CandidateRollbackRecord(
    { ...body, recordSha256: objectSha256(body) },
    {
      previousManifest,
      approvalSha256,
      planSha256,
      deploymentEvidenceSha256,
    },
  );
};

const observedRollbackState = (value, previousManifest, candidateRecord) => {
  if (
    !exactKeys(value, ['api', 'worker', 'web', 'pending', 'dataFactsSha256']) ||
    !exactKeys(value.api, ['functionName', 'aliasName', 'version']) ||
    !exactKeys(value.worker, ['functionName', 'aliasName', 'version']) ||
    !LAMBDA_FUNCTION_NAME.test(value.api.functionName ?? '') ||
    !LAMBDA_ALIAS_NAME.test(value.api.aliasName ?? '') ||
    !LAMBDA_VERSION.test(value.api.version ?? '') ||
    !LAMBDA_FUNCTION_NAME.test(value.worker.functionName ?? '') ||
    !LAMBDA_ALIAS_NAME.test(value.worker.aliasName ?? '') ||
    !LAMBDA_VERSION.test(value.worker.version ?? '') ||
    !exactKeys(value.web, ['bucketName', 'distributionId', 'objects']) ||
    !S3_BUCKET.test(value.web.bucketName ?? '') ||
    !CLOUDFRONT_DISTRIBUTION_ID.test(value.web.distributionId ?? '') ||
    !Array.isArray(value.web.objects) ||
    value.web.objects.map(({ key } = {}) => key).join('\0') !==
      candidateRecord.resources.web.objects.map(({ key }) => key).join('\0') ||
    value.web.objects.some(
      (entry) =>
        !exactKeys(entry, ['key', 'versionId', 'contentSha256']) ||
        !WEB_OBJECT_KEY.test(entry.key ?? '') ||
        !S3_VERSION_ID.test(entry.versionId ?? '') ||
        !SHA256.test(entry.contentSha256 ?? ''),
    ) ||
    !exactKeys(value.pending, [
      'observedAtUtc',
      'trackedCount',
      'oldestAgeSeconds',
      'snapshotSha256',
    ]) ||
    !isoUtc(value.pending.observedAtUtc) ||
    !Number.isSafeInteger(value.pending.trackedCount) ||
    value.pending.trackedCount < 0 ||
    !Number.isSafeInteger(value.pending.oldestAgeSeconds) ||
    value.pending.oldestAgeSeconds < 0 ||
    !SHA256.test(value.pending.snapshotSha256 ?? '') ||
    !SHA256.test(value.dataFactsSha256 ?? '')
  ) {
    fail('E7_ROLLBACK_OBSERVED_STATE_INVALID');
  }
  const coordinates = [previousManifest.resources, candidateRecord.resources];
  if (
    coordinates.some(
      (resources) =>
        value.api.functionName !== resources.api.functionName ||
        value.api.aliasName !== resources.api.aliasName ||
        value.worker.functionName !== resources.worker.functionName ||
        value.worker.aliasName !== resources.worker.aliasName ||
        value.web.bucketName !== resources.web.bucketName ||
        value.web.distributionId !== resources.web.distributionId,
    )
  ) {
    fail('E7_ROLLBACK_OBSERVED_STATE_TARGET_MISMATCH');
  }
  return value;
};

export const createStage7VersionedRollbackPlan = ({
  direction,
  purpose = 'REHEARSAL',
  previousManifest,
  candidateRecord,
  currentState,
  pendingBaseline = currentState?.pending,
}) => {
  validateStage7PreviousReleaseManifest(previousManifest);
  validateStage7CandidateRollbackRecord(candidateRecord, { previousManifest });
  observedRollbackState(currentState, previousManifest, candidateRecord);
  if (!['ROLLBACK_TO_PREVIOUS', 'REPROMOTE_CANDIDATE'].includes(direction)) {
    fail('E7_ROLLBACK_DIRECTION_INVALID');
  }
  if (!['REHEARSAL', 'EMERGENCY_RECOVERY'].includes(purpose)) {
    fail('E7_ROLLBACK_PURPOSE_INVALID');
  }
  const rollback = direction === 'ROLLBACK_TO_PREVIOUS';
  const lockedBaselineState = {
    ...currentState,
    pending: pendingBaseline,
  };
  observedRollbackState(lockedBaselineState, previousManifest, candidateRecord);
  if (rollback && purpose === 'REHEARSAL' && pendingBaseline.trackedCount < 1) {
    fail('E7_ROLLBACK_PENDING_REHEARSAL_REQUIRED');
  }
  const source = rollback ? candidateRecord.resources : previousManifest.resources;
  const target = rollback ? previousManifest.resources : candidateRecord.resources;
  const sourceIdentity = rollback ? previousManifest.target : previousManifest.previous;
  const targetIdentity = rollback ? previousManifest.previous : previousManifest.target;
  const currentByKey = new Map(currentState.web.objects.map((entry) => [entry.key, entry]));
  const sourceByKey = new Map(source.web.objects.map((entry) => [entry.key, entry]));
  const aliasState = (current, from, to) => {
    if (current === from) return 'SOURCE';
    if (current === to) return 'TARGET';
    fail('E7_ROLLBACK_PARTIAL_OR_UNKNOWN_STATE');
  };
  const componentStates = [
    aliasState(currentState.api.version, source.api.version, target.api.version),
    aliasState(currentState.worker.version, source.worker.version, target.worker.version),
    ...target.web.objects.map((entry) =>
      aliasState(
        currentByKey.get(entry.key)?.contentSha256,
        sourceByKey.get(entry.key)?.contentSha256,
        entry.contentSha256,
      ),
    ),
  ];
  const decision = componentStates.every((state) => state === 'SOURCE')
    ? 'APPLY'
    : componentStates.every((state) => state === 'TARGET')
      ? 'NOOP_ALREADY_APPLIED'
      : 'RESUME_PARTIAL';
  const operationRequired = (state) => state === 'SOURCE';
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_PLAN',
    direction,
    purpose,
    decision,
    fromReleaseId: sourceIdentity.releaseId,
    toReleaseId: targetIdentity.releaseId,
    previousReleaseManifestSha256: previousManifest.manifestSha256,
    candidateRecordSha256: candidateRecord.recordSha256,
    aliases: {
      api: {
        functionName: target.api.functionName,
        aliasName: target.api.aliasName,
        fromVersion: source.api.version,
        toVersion: target.api.version,
        changed: operationRequired(componentStates[0]),
      },
      worker: {
        functionName: target.worker.functionName,
        aliasName: target.worker.aliasName,
        fromVersion: source.worker.version,
        toVersion: target.worker.version,
        changed: operationRequired(componentStates[1]),
      },
    },
    web: {
      bucketName: target.web.bucketName,
      distributionId: target.web.distributionId,
      objects: target.web.objects.map((entry) => ({
        key: entry.key,
        fromVersionId: sourceByKey.get(entry.key).versionId,
        toVersionId: entry.versionId,
        fromContentSha256: sourceByKey.get(entry.key).contentSha256,
        toContentSha256: entry.contentSha256,
        changed: operationRequired(
          aliasState(
            currentByKey.get(entry.key)?.contentSha256,
            sourceByKey.get(entry.key)?.contentSha256,
            entry.contentSha256,
          ),
        ),
      })),
      invalidationPaths: [...target.web.mutableInvalidationPaths],
    },
    pendingBaseline: { ...pendingBaseline },
    dataFactsSha256: currentState.dataFactsSha256,
    dataAction: 'NONE_FORWARD_ONLY',
    stacksDeleted: 0,
    containsSensitiveData: false,
  };
  return { ...body, planSha256: objectSha256(body) };
};

export const validateStage7VersionedRollbackCheckpoint = (
  checkpoint,
  { plan, previousManifest, candidateRecord },
) => {
  const expectedPlan = createStage7VersionedRollbackPlan({
    direction: plan?.direction,
    purpose: plan?.purpose,
    previousManifest,
    candidateRecord,
    currentState: {
      api: {
        functionName: plan?.aliases?.api?.functionName,
        aliasName: plan?.aliases?.api?.aliasName,
        version: plan?.aliases?.api?.changed
          ? plan?.aliases?.api?.fromVersion
          : plan?.aliases?.api?.toVersion,
      },
      worker: {
        functionName: plan?.aliases?.worker?.functionName,
        aliasName: plan?.aliases?.worker?.aliasName,
        version: plan?.aliases?.worker?.changed
          ? plan?.aliases?.worker?.fromVersion
          : plan?.aliases?.worker?.toVersion,
      },
      web: {
        bucketName: plan?.web?.bucketName,
        distributionId: plan?.web?.distributionId,
        objects: (plan?.web?.objects ?? []).map((entry) => ({
          key: entry.key,
          versionId: entry.changed ? entry.fromVersionId : entry.toVersionId,
          contentSha256: entry.changed ? entry.fromContentSha256 : entry.toContentSha256,
        })),
      },
      pending: plan?.pendingBaseline,
      dataFactsSha256: plan?.dataFactsSha256,
    },
  });
  if (canonicalJson(plan) !== canonicalJson(expectedPlan)) fail('E7_ROLLBACK_PLAN_INVALID');
  if (plan.purpose !== 'REHEARSAL') fail('E7_ROLLBACK_PLAN_INVALID');
  const applied = plan.decision !== 'NOOP_ALREADY_APPLIED';
  const destination =
    plan.direction === 'ROLLBACK_TO_PREVIOUS'
      ? previousManifest.resources
      : candidateRecord.resources;
  const expectedScenarios =
    plan.direction === 'ROLLBACK_TO_PREVIOUS'
      ? ['RB-E7-01', 'RB-E7-03', 'RB-E7-05', 'RB-E7-07']
      : ['RB-E7-02', 'RB-E7-04', 'RB-E7-05', 'RB-E7-07'];
  const checkpointWebObjectsValid =
    Array.isArray(checkpoint?.web?.objects) &&
    checkpoint.web.objects.length === destination.web.objects.length &&
    checkpoint.web.objects.every((entry, index) => {
      const expected = destination.web.objects[index];
      return (
        exactKeys(entry, ['key', 'sourceVersionId', 'activeVersionId', 'contentSha256', 'bytes']) &&
        entry.key === expected.key &&
        entry.sourceVersionId === expected.versionId &&
        S3_VERSION_ID.test(entry.activeVersionId ?? '') &&
        entry.contentSha256 === expected.contentSha256 &&
        entry.bytes === expected.bytes
      );
    });
  if (
    !exactKeys(checkpoint, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'direction',
      'decision',
      'scenarioIds',
      'planSha256',
      'startedAtUtc',
      'completedAtUtc',
      'fromReleaseId',
      'toReleaseId',
      'aliases',
      'web',
      'pendingIntegrity',
      'dataFactsSha256',
      'dataFactsChanged',
      'dataRollbackPerformed',
      'stacksDeleted',
      'smoke',
      'containsSensitiveData',
      'checkpointSha256',
    ]) ||
    checkpoint.schemaVersion !== 1 ||
    checkpoint.stage !== 7 ||
    checkpoint.kind !== 'VERSIONED_ROLLBACK_CHECKPOINT' ||
    checkpoint.status !== 'PASS' ||
    checkpoint.direction !== plan.direction ||
    checkpoint.decision !== (applied ? 'APPLIED_AND_VERIFIED' : 'ALREADY_APPLIED_AND_VERIFIED') ||
    checkpoint.scenarioIds?.join('\0') !== expectedScenarios.join('\0') ||
    checkpoint.planSha256 !== plan.planSha256 ||
    !isoUtc(checkpoint.startedAtUtc) ||
    !isoUtc(checkpoint.completedAtUtc) ||
    Date.parse(checkpoint.completedAtUtc) < Date.parse(checkpoint.startedAtUtc) ||
    checkpoint.fromReleaseId !== plan.fromReleaseId ||
    checkpoint.toReleaseId !== plan.toReleaseId ||
    !exactKeys(checkpoint.aliases, ['api', 'worker']) ||
    !exactKeys(checkpoint.aliases.api, ['functionName', 'aliasName', 'version']) ||
    !exactKeys(checkpoint.aliases.worker, ['functionName', 'aliasName', 'version']) ||
    checkpoint.aliases.api.functionName !== destination.api.functionName ||
    checkpoint.aliases.api.aliasName !== destination.api.aliasName ||
    checkpoint.aliases.api.version !== destination.api.version ||
    checkpoint.aliases.worker.functionName !== destination.worker.functionName ||
    checkpoint.aliases.worker.aliasName !== destination.worker.aliasName ||
    checkpoint.aliases.worker.version !== destination.worker.version ||
    !exactKeys(checkpoint.web, ['bucketName', 'distributionId', 'objects', 'invalidation']) ||
    checkpoint.web.bucketName !== destination.web.bucketName ||
    checkpoint.web.distributionId !== destination.web.distributionId ||
    !checkpointWebObjectsValid ||
    !exactKeys(checkpoint.web.invalidation, ['status', 'idSha256', 'paths']) ||
    checkpoint.web.invalidation.status !== (applied ? 'COMPLETED' : 'NOT_REQUIRED') ||
    (applied
      ? !SHA256.test(checkpoint.web.invalidation.idSha256 ?? '')
      : checkpoint.web.invalidation.idSha256 !== null) ||
    checkpoint.web.invalidation.paths?.join('\0') !==
      (applied ? destination.web.mutableInvalidationPaths : []).join('\0') ||
    !exactKeys(checkpoint.pendingIntegrity, [
      'status',
      'beforeSnapshotSha256',
      'afterSnapshotSha256',
      'correlationEvidenceSha256',
      'trackedBefore',
      'stillPending',
      'reconciled',
      'orphaned',
      'duplicateEffects',
      'lostFacts',
    ]) ||
    checkpoint.pendingIntegrity.status !== 'PASS' ||
    checkpoint.pendingIntegrity.beforeSnapshotSha256 !== plan.pendingBaseline.snapshotSha256 ||
    !SHA256.test(checkpoint.pendingIntegrity.afterSnapshotSha256 ?? '') ||
    !SHA256.test(checkpoint.pendingIntegrity.correlationEvidenceSha256 ?? '') ||
    checkpoint.pendingIntegrity.trackedBefore !== plan.pendingBaseline.trackedCount ||
    !Number.isSafeInteger(checkpoint.pendingIntegrity.stillPending) ||
    checkpoint.pendingIntegrity.stillPending < 0 ||
    !Number.isSafeInteger(checkpoint.pendingIntegrity.reconciled) ||
    checkpoint.pendingIntegrity.reconciled < 0 ||
    checkpoint.pendingIntegrity.trackedBefore !==
      checkpoint.pendingIntegrity.stillPending + checkpoint.pendingIntegrity.reconciled ||
    (plan.direction === 'ROLLBACK_TO_PREVIOUS' &&
      (checkpoint.pendingIntegrity.trackedBefore < 1 ||
        checkpoint.pendingIntegrity.stillPending !== 0 ||
        checkpoint.pendingIntegrity.reconciled !== checkpoint.pendingIntegrity.trackedBefore)) ||
    checkpoint.pendingIntegrity.orphaned !== 0 ||
    checkpoint.pendingIntegrity.duplicateEffects !== 0 ||
    checkpoint.pendingIntegrity.lostFacts !== 0 ||
    checkpoint.dataFactsSha256 !== plan.dataFactsSha256 ||
    checkpoint.dataFactsChanged !== false ||
    checkpoint.dataRollbackPerformed !== false ||
    checkpoint.stacksDeleted !== 0 ||
    !exactKeys(checkpoint.smoke, ['status', 'releaseId', 'evidenceSha256']) ||
    checkpoint.smoke.status !== 'PASS' ||
    checkpoint.smoke.releaseId !== plan.toReleaseId ||
    !SHA256.test(checkpoint.smoke.evidenceSha256 ?? '') ||
    checkpoint.containsSensitiveData !== false
  ) {
    fail('E7_VERSIONED_ROLLBACK_CHECKPOINT_INVALID');
  }
  const body = { ...checkpoint };
  delete body.checkpointSha256;
  if (checkpoint.checkpointSha256 !== objectSha256(body)) {
    fail('E7_VERSIONED_ROLLBACK_CHECKPOINT_DIGEST_INVALID');
  }
  return checkpoint;
};

const versionedRollbackTransitionBody = (transition) => {
  const body = { ...transition };
  delete body.transitionSha256;
  return body;
};

export const validateStage7VersionedRollbackTransition = (
  transition,
  { plan, previousManifest, candidateRecord },
) => {
  if (
    !exactKeys(transition, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'direction',
      'decision',
      'planSha256',
      'startedAtUtc',
      'completedAtUtc',
      'fromReleaseId',
      'toReleaseId',
      'aliases',
      'web',
      'pendingIntegrity',
      'dataFactsSha256',
      'dataFactsChanged',
      'dataRollbackPerformed',
      'stacksDeleted',
      'containsSensitiveData',
      'transitionSha256',
    ]) ||
    transition.kind !== 'VERSIONED_ROLLBACK_AWS_TRANSITION' ||
    transition.status !== 'AWS_VERIFIED_PENDING_READ_SMOKE' ||
    transition.transitionSha256 !== objectSha256(versionedRollbackTransitionBody(transition))
  ) {
    fail('E7_VERSIONED_ROLLBACK_TRANSITION_INVALID');
  }
  const checkpointBody = {
    ...versionedRollbackTransitionBody(transition),
    kind: 'VERSIONED_ROLLBACK_CHECKPOINT',
    status: 'PASS',
    scenarioIds:
      transition.direction === 'ROLLBACK_TO_PREVIOUS'
        ? ['RB-E7-01', 'RB-E7-03', 'RB-E7-05', 'RB-E7-07']
        : ['RB-E7-02', 'RB-E7-04', 'RB-E7-05', 'RB-E7-07'],
    smoke: {
      status: 'PASS',
      releaseId: transition.toReleaseId,
      evidenceSha256: '0'.repeat(64),
    },
  };
  const checkpoint = {
    ...checkpointBody,
    checkpointSha256: objectSha256(checkpointBody),
  };
  validateStage7VersionedRollbackCheckpoint(checkpoint, {
    plan,
    previousManifest,
    candidateRecord,
  });
  return transition;
};

export const createStage7VersionedRollbackTransition = ({
  plan,
  previousManifest,
  candidateRecord,
  startedAtUtc,
  completedAtUtc,
  aliases,
  web,
  pendingIntegrity,
}) => {
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_AWS_TRANSITION',
    status: 'AWS_VERIFIED_PENDING_READ_SMOKE',
    direction: plan.direction,
    decision:
      plan.decision === 'NOOP_ALREADY_APPLIED'
        ? 'ALREADY_APPLIED_AND_VERIFIED'
        : 'APPLIED_AND_VERIFIED',
    planSha256: plan.planSha256,
    startedAtUtc,
    completedAtUtc,
    fromReleaseId: plan.fromReleaseId,
    toReleaseId: plan.toReleaseId,
    aliases,
    web,
    pendingIntegrity,
    dataFactsSha256: plan.dataFactsSha256,
    dataFactsChanged: false,
    dataRollbackPerformed: false,
    stacksDeleted: 0,
    containsSensitiveData: false,
  };
  return validateStage7VersionedRollbackTransition(
    { ...body, transitionSha256: objectSha256(body) },
    { plan, previousManifest, candidateRecord },
  );
};

const versionedRollbackRehearsalBody = (rehearsal) => {
  const body = { ...rehearsal };
  delete body.rehearsalSha256;
  return body;
};

/**
 * Final, unified evidence for the four real version transitions plus the
 * pending-payment integrity scenario. Both checkpoints are retained whole so
 * a consumer can independently replay every canonical validation.
 */
export const validateStage7VersionedRollbackRehearsal = (
  rehearsal,
  { previousManifest, candidateRecord },
) => {
  validateStage7PreviousReleaseManifest(previousManifest);
  validateStage7CandidateRollbackRecord(candidateRecord, { previousManifest });
  if (
    !exactKeys(rehearsal, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scenarioIds',
      'pendingScenarioIds',
      'previousReleaseManifestSha256',
      'candidateRecordSha256',
      'approvalSha256',
      'approvedPlanSha256',
      'deploymentEvidenceSha256',
      'rollback',
      'repromotion',
      'dataPolicy',
      'dataRollbackPerformed',
      'stacksDeleted',
      'completedAtUtc',
      'containsSensitiveData',
      'rehearsalSha256',
    ]) ||
    rehearsal.schemaVersion !== 1 ||
    rehearsal.stage !== 7 ||
    rehearsal.kind !== 'VERSIONED_ROLLBACK_REHEARSAL' ||
    rehearsal.status !== 'BLOCKED_REQUIRED_SCENARIOS' ||
    rehearsal.scenarioIds?.join('\0') !==
      ['RB-E7-01', 'RB-E7-02', 'RB-E7-03', 'RB-E7-04', 'RB-E7-05', 'RB-E7-07'].join('\0') ||
    rehearsal.pendingScenarioIds?.join('\0') !== ['RB-E7-06', 'RB-E7-08'].join('\0') ||
    rehearsal.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    rehearsal.candidateRecordSha256 !== candidateRecord.recordSha256 ||
    rehearsal.approvalSha256 !== candidateRecord.approvalSha256 ||
    rehearsal.approvedPlanSha256 !== candidateRecord.planSha256 ||
    rehearsal.deploymentEvidenceSha256 !== candidateRecord.deploymentEvidenceSha256 ||
    !exactKeys(rehearsal.rollback, ['plan', 'checkpoint']) ||
    !exactKeys(rehearsal.repromotion, ['plan', 'checkpoint']) ||
    rehearsal.rollback.plan?.direction !== 'ROLLBACK_TO_PREVIOUS' ||
    rehearsal.repromotion.plan?.direction !== 'REPROMOTE_CANDIDATE' ||
    rehearsal.rollback.plan?.toReleaseId !== previousManifest.previous.releaseId ||
    rehearsal.repromotion.plan?.toReleaseId !== previousManifest.target.releaseId ||
    rehearsal.rollback.checkpoint?.completedAtUtc >
      rehearsal.repromotion.checkpoint?.startedAtUtc ||
    rehearsal.dataPolicy !== 'NO_ROLLBACK_FORWARD_ONLY' ||
    rehearsal.dataRollbackPerformed !== false ||
    rehearsal.stacksDeleted !== 0 ||
    !isoUtc(rehearsal.completedAtUtc) ||
    rehearsal.completedAtUtc !== rehearsal.repromotion.checkpoint?.completedAtUtc ||
    rehearsal.containsSensitiveData !== false
  ) {
    fail('E7_VERSIONED_ROLLBACK_REHEARSAL_INVALID');
  }
  validateStage7VersionedRollbackCheckpoint(rehearsal.rollback.checkpoint, {
    plan: rehearsal.rollback.plan,
    previousManifest,
    candidateRecord,
  });
  validateStage7VersionedRollbackCheckpoint(rehearsal.repromotion.checkpoint, {
    plan: rehearsal.repromotion.plan,
    previousManifest,
    candidateRecord,
  });
  if (
    rehearsal.rollback.checkpoint.pendingIntegrity.status !== 'PASS' ||
    rehearsal.repromotion.checkpoint.pendingIntegrity.status !== 'PASS' ||
    rehearsal.rollback.checkpoint.dataFactsSha256 !==
      rehearsal.repromotion.checkpoint.dataFactsSha256 ||
    rehearsal.rehearsalSha256 !== objectSha256(versionedRollbackRehearsalBody(rehearsal))
  ) {
    fail('E7_VERSIONED_ROLLBACK_REHEARSAL_DIGEST_INVALID');
  }
  return rehearsal;
};

export const createStage7VersionedRollbackRehearsal = ({
  previousManifest,
  candidateRecord,
  rollbackPlan,
  rollbackCheckpoint,
  repromotionPlan,
  repromotionCheckpoint,
}) => {
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_REHEARSAL',
    status: 'BLOCKED_REQUIRED_SCENARIOS',
    scenarioIds: ['RB-E7-01', 'RB-E7-02', 'RB-E7-03', 'RB-E7-04', 'RB-E7-05', 'RB-E7-07'],
    pendingScenarioIds: ['RB-E7-06', 'RB-E7-08'],
    previousReleaseManifestSha256: previousManifest.manifestSha256,
    candidateRecordSha256: candidateRecord.recordSha256,
    approvalSha256: candidateRecord.approvalSha256,
    approvedPlanSha256: candidateRecord.planSha256,
    deploymentEvidenceSha256: candidateRecord.deploymentEvidenceSha256,
    rollback: { plan: rollbackPlan, checkpoint: rollbackCheckpoint },
    repromotion: { plan: repromotionPlan, checkpoint: repromotionCheckpoint },
    dataPolicy: 'NO_ROLLBACK_FORWARD_ONLY',
    dataRollbackPerformed: false,
    stacksDeleted: 0,
    completedAtUtc: repromotionCheckpoint.completedAtUtc,
    containsSensitiveData: false,
  };
  return validateStage7VersionedRollbackRehearsal(
    { ...body, rehearsalSha256: objectSha256(body) },
    { previousManifest, candidateRecord },
  );
};

export const createFreezeManifest = ({
  config,
  e6Manifest,
  candidate,
  releaseTag,
  builtAt = new Date().toISOString(),
  sourceArtifactId,
  sourceArtifactSha256,
  preFreezeEvidenceSha256 = null,
  awsCliVersion,
  paths,
  rootDirectory = workspaceRoot,
}) => {
  validateStage7Config(config, { now: new Date(builtAt) });
  const e6 = assessStage6Manifest(e6Manifest);
  const fullRelease = config.authorization.scope === 'FULL_RELEASE_VERSIONED_UPDATE';
  const prerelease = config.authorization.scope === 'EPHEMERAL_PRERELEASE';
  if (
    (!fullRelease && !prerelease) ||
    (fullRelease && e6.status !== 'PASS') ||
    (prerelease && e6.status !== 'CONDITIONAL_GO')
  ) {
    fail('E7_FREEZE_SCOPE_GATE_INVALID');
  }
  if (
    !object(candidate) ||
    !SHA.test(candidate.commitSha ?? '') ||
    !SHA.test(candidate.treeSha ?? '') ||
    candidate.workingTree !== 'CLEAN' ||
    candidate.changedFiles !== 0 ||
    e6.candidate.commitSha !== candidate.commitSha ||
    e6.candidate.treeSha !== candidate.treeSha
  ) {
    fail('E7_FREEZE_CANDIDATE_MISMATCH');
  }
  if (
    (fullRelease && !RELEASE_TAG.test(releaseTag ?? '')) ||
    (prerelease && releaseTag !== null && releaseTag !== undefined)
  ) {
    fail('E7_RELEASE_TAG_INVALID');
  }
  if (!isoUtc(builtAt)) fail('E7_BUILD_TIMESTAMP_INVALID');
  if (!/^[0-9]{1,20}$/u.test(sourceArtifactId ?? '')) fail('E7_SOURCE_ARTIFACT_ID_INVALID');
  if (!SHA256.test(sourceArtifactSha256 ?? '')) fail('E7_SOURCE_ARTIFACT_DIGEST_INVALID');
  if (
    (fullRelease && !SHA256.test(preFreezeEvidenceSha256 ?? '')) ||
    (prerelease && preFreezeEvidenceSha256 !== null)
  ) {
    fail('E7_PRE_FREEZE_EVIDENCE_DIGEST_INVALID');
  }
  if (!SEMVER.test(awsCliVersion ?? '')) fail('E7_AWS_CLI_VERSION_INVALID');
  if (
    !exactKeys(paths, [
      'web',
      'api',
      'worker',
      'iac',
      'lockfile',
      'openapi',
      'generatedClient',
      'publicConfig',
    ])
  ) {
    fail('E7_FREEZE_PATHS_INVALID');
  }

  const rootPackage = JSON.parse(readFileSync(path.resolve(rootDirectory, 'package.json'), 'utf8'));
  const infraPackage = JSON.parse(
    readFileSync(path.resolve(rootDirectory, 'infra', 'package.json'), 'utf8'),
  );
  const pinnedNode = readFileSync(path.resolve(rootDirectory, '.node-version'), 'utf8').trim();
  if (process.version !== `v${pinnedNode}`) fail('E7_NODE_VERSION_NOT_PINNED');
  const artifacts = ['web', 'api', 'worker', 'iac'].map((name) => ({
    name,
    ...hashArtifactPath(paths[name], { rootDirectory }),
  }));
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'BUILD_ONCE_FREEZE',
    releaseId: releaseId(builtAt, candidate.commitSha),
    candidateSha: candidate.commitSha,
    candidateTreeSha: candidate.treeSha,
    releaseTag: fullRelease ? releaseTag : null,
    environment: config.environment,
    authorizationScope: config.authorization.scope,
    region: config.aws.region,
    sourceRunId: e6.runId,
    sourceArtifactId,
    sourceArtifactSha256,
    preFreezeEvidenceSha256,
    builtAt,
    configSha256: objectSha256(config),
    lockfileSha256: hashArtifactPath(paths.lockfile, { rootDirectory }).sha256,
    openApiSha256: hashArtifactPath(paths.openapi, { rootDirectory }).sha256,
    generatedClientSha256: hashArtifactPath(paths.generatedClient, { rootDirectory }).sha256,
    publicConfigSha256: hashArtifactPath(paths.publicConfig, { rootDirectory }).sha256,
    templateSha256: artifacts[3].sha256,
    stage6Gates: { ...e6Manifest.gates },
    toolchain: {
      node: process.version,
      packageManager: rootPackage.packageManager,
      cdkCli: infraPackage.devDependencies?.['aws-cdk'],
      cdkLibrary: infraPackage.dependencies?.['aws-cdk-lib'],
      awsCli: awsCliVersion,
    },
    artifacts,
    controlInventory: {
      artifacts: {
        total: STAGE7_ARTIFACTS.length,
        idsSha256: objectSha256(STAGE7_ARTIFACTS.map(({ id }) => id)),
      },
      evidence: {
        total: STAGE7_EVIDENCE.length,
        idsSha256: objectSha256(STAGE7_EVIDENCE.map(({ id }) => id)),
      },
      audits: {
        total: STAGE7_AUDITS.length,
        idsSha256: objectSha256(STAGE7_AUDITS.map(({ id }) => id)),
      },
    },
    releaseMode: fullRelease ? 'VERSIONED_UPDATE' : 'INITIAL',
    updateReleaseSupported: fullRelease,
    updateReleaseUnsupportedReason: fullRelease ? null : 'EPHEMERAL_PRERELEASE_INITIAL_ONLY',
    buildOnce: { immutable: true, rebuilt: false },
    containsSensitiveData: false,
  };
  return validateFreezeManifest({ ...body, manifestSha256: objectSha256(body) });
};

export const createLocalPreflight = ({
  config,
  e6Manifest,
  freezeManifest,
  previousReleaseManifest,
  prereleaseSafety,
  candidate,
  now = new Date(),
}) => {
  validateStage7Config(config, { now });
  const e6 = assessStage6Manifest(e6Manifest);
  const issues = [];
  if (
    !object(candidate) ||
    !SHA.test(candidate.commitSha ?? '') ||
    !SHA.test(candidate.treeSha ?? '') ||
    candidate.workingTree !== 'CLEAN' ||
    candidate.changedFiles !== 0
  ) {
    issues.push('E7_WORKTREE_NOT_CLEAN');
  }
  if (
    e6.candidate !== undefined &&
    (e6.candidate.commitSha !== candidate?.commitSha || e6.candidate.treeSha !== candidate?.treeSha)
  ) {
    issues.push('E7_E6_CANDIDATE_MISMATCH');
  }
  if (e6.status === 'FAIL') issues.push(e6.code);
  const nowTime = now instanceof Date ? now.getTime() : Number.NaN;
  if (
    config.authorization.scope !== 'NON_MUTATING_PLAN' &&
    (nowTime < Date.parse(config.window.startsAtUtc) ||
      nowTime >= Date.parse(config.window.endsAtUtc))
  ) {
    issues.push('E7_OUTSIDE_RELEASE_WINDOW');
  }

  if (
    e6.status === 'CONDITIONAL_GO' &&
    config.authorization.scope === 'FULL_RELEASE_VERSIONED_UPDATE'
  ) {
    issues.push('E7_FULL_RELEASE_BLOCKED_BY_E6');
  }

  // Entry preflight is intentionally non-mutating and must remain satisfiable
  // before the build-once freeze exists. N-1 and prerelease recovery controls
  // become mandatory once a freeze is supplied; mutation operations perform
  // the stronger AWS/artifact checks again immediately before changing state.
  if (
    config.authorization.scope === 'FULL_RELEASE_VERSIONED_UPDATE' &&
    freezeManifest !== undefined
  ) {
    if (previousReleaseManifest === undefined) {
      issues.push('E7_PREVIOUS_APPROVED_RELEASE_REQUIRED');
    } else {
      try {
        validateStage7PreviousReleaseForTarget(previousReleaseManifest, {
          config,
          freezeManifest,
        });
      } catch (error) {
        if (!(error instanceof Stage7Error)) throw error;
        issues.push(error.code);
      }
    }
  }
  if (config.authorization.scope === 'EPHEMERAL_PRERELEASE' && freezeManifest !== undefined) {
    if (
      !exactKeys(prereleaseSafety, [
        'readiness',
        'sourceBindings',
        'watchdogRoleArn',
        'iamEffectivePermissions',
        'githubRunId',
        'githubRunAttempt',
      ])
    ) {
      issues.push('E7_PRERELEASE_SAFETY_READINESS_REQUIRED');
    } else {
      try {
        validatePrereleaseSafetyReadinessContract(prereleaseSafety.readiness, {
          config,
          freeze: freezeManifest,
          sourceBindings: prereleaseSafety.sourceBindings,
          watchdogRoleArn: prereleaseSafety.watchdogRoleArn,
          iamEffectivePermissions: prereleaseSafety.iamEffectivePermissions,
          expectedGithubRunId: prereleaseSafety.githubRunId,
          expectedGithubRunAttempt: prereleaseSafety.githubRunAttempt,
          now,
        });
      } catch (error) {
        if (!(error instanceof PrereleaseSafetyContractError)) throw error;
        issues.push(error.code);
      }
    }
  }

  let decision = 'NOT_READY';
  if (issues.length === 0 && config.authorization.scope === 'NON_MUTATING_PLAN') {
    decision = 'READY_FOR_NON_MUTATING_PLAN';
  } else if (
    issues.length === 0 &&
    e6.status === 'CONDITIONAL_GO' &&
    config.authorization.scope === 'EPHEMERAL_PRERELEASE'
  ) {
    decision = 'READY_FOR_AUTHORIZED_EPHEMERAL_PREFLIGHT';
  } else if (
    issues.length === 0 &&
    e6.status === 'PASS' &&
    config.authorization.scope === 'FULL_RELEASE_VERSIONED_UPDATE'
  ) {
    if (freezeManifest === undefined) {
      decision = 'READY_FOR_BUILD_FREEZE';
    } else {
      validateFreezeManifest(freezeManifest);
      if (
        freezeManifest.candidateSha !== candidate.commitSha ||
        freezeManifest.candidateTreeSha !== candidate.treeSha ||
        freezeManifest.environment !== config.environment ||
        freezeManifest.region !== config.aws.region ||
        freezeManifest.sourceRunId !== e6.runId ||
        freezeManifest.configSha256 !== objectSha256(config)
      ) {
        issues.push('E7_FREEZE_MANIFEST_MISMATCH');
      } else {
        decision = 'READY_FOR_CLOUD_PREFLIGHT';
      }
    }
  } else if (
    issues.length === 0 &&
    e6.status === 'CONDITIONAL_GO' &&
    config.authorization.scope === 'FULL_RELEASE_VERSIONED_UPDATE'
  ) {
    issues.push('E7_FULL_RELEASE_BLOCKED_BY_E6');
  } else if (issues.length === 0) {
    issues.push('E7_AUTHORIZATION_SCOPE_GATE_MISMATCH');
  }

  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'LOCAL_PREFLIGHT',
    generatedAt: now.toISOString(),
    candidate,
    stage6: { status: e6.status, code: e6.code, runId: e6.runId ?? null },
    authorization: stage7ConfigSummary(config),
    decision: issues.length === 0 ? decision : 'NOT_READY',
    issues,
    cloudChecks: {
      callerIdentity: 'NOT_RUN',
      accountAllowlist: 'NOT_RUN',
      region: 'NOT_RUN',
      roleTrust: 'NOT_RUN',
      bootstrap: 'NOT_RUN',
      quotas: 'NOT_RUN',
    },
    gates: {
      'GATE-E7-01': 'NOT_RUN',
      'GATE-E7-02': 'NOT_RUN',
      'GATE-E7-03': 'NOT_RUN',
    },
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
};

const statusFromRequired = (states) => {
  if (states.some((state) => ['FAIL', 'FAILED'].includes(state))) return 'FAIL';
  if (states.includes('BLOCKED_AUTH')) return 'BLOCKED_AUTH';
  return states.every((state) => ['PASS', 'VERIFIED', 'NOT_APPLICABLE_APPROVED'].includes(state))
    ? 'PASS'
    : 'NOT_RUN';
};

const gateEvidenceIds = {
  one: [...expectedIds('EVD-E7', 13), 'EVD-E7-54'],
  two: expectedIds('EVD-E7', 45).slice(13),
  three: expectedIds('EVD-E7', 54).slice(45),
};

export const createStage7Index = ({ entryGate, artifactStates = {}, evidenceStates = {} }) => {
  if (!['PASS', 'CONDITIONAL_GO', 'FAIL', 'NOT_RUN'].includes(entryGate)) {
    fail('E7_ENTRY_GATE_INVALID');
  }
  if (!object(artifactStates) || !object(evidenceStates)) fail('E7_INDEX_STATE_INVALID');
  const artifactIds = new Set(STAGE7_ARTIFACTS.map(({ id }) => id));
  const evidenceIds = new Set(STAGE7_EVIDENCE.map(({ id }) => id));
  if (
    Object.entries(artifactStates).some(
      ([id, status]) => !artifactIds.has(id) || !ARTIFACT_STATES.includes(status),
    ) ||
    Object.entries(evidenceStates).some(
      ([id, status]) =>
        !evidenceIds.has(id) ||
        ['EVD-E7-55', 'EVD-E7-56', 'EVD-E7-57'].includes(id) ||
        !EVIDENCE_STATES.includes(status),
    )
  ) {
    fail('E7_INDEX_STATE_INVALID');
  }

  const artifacts = STAGE7_ARTIFACTS.map((entry) => ({
    ...entry,
    status: artifactStates[entry.id] ?? 'PLANNED',
  }));
  const evidence = STAGE7_EVIDENCE.map((entry) => ({
    ...entry,
    status: evidenceStates[entry.id] ?? 'NOT_RUN',
  }));
  const evidenceById = new Map(evidence.map((entry) => [entry.id, entry]));

  const gate1 =
    entryGate === 'FAIL'
      ? 'FAIL'
      : entryGate === 'CONDITIONAL_GO'
        ? 'BLOCKED_AUTH'
        : entryGate === 'NOT_RUN'
          ? 'NOT_RUN'
          : statusFromRequired(gateEvidenceIds.one.map((id) => evidenceById.get(id).status));
  const gate2 =
    gate1 === 'FAIL'
      ? 'FAIL'
      : gate1 === 'BLOCKED_AUTH'
        ? 'BLOCKED_AUTH'
        : gate1 !== 'PASS'
          ? 'NOT_RUN'
          : statusFromRequired(gateEvidenceIds.two.map((id) => evidenceById.get(id).status));
  const gate3Prerequisites = [
    ...gateEvidenceIds.three.map((id) => evidenceById.get(id).status),
    ...artifacts.slice(0, 17).map(({ status }) => status),
  ];
  const gate3 =
    gate1 === 'FAIL' || gate2 === 'FAIL'
      ? 'FAIL'
      : gate1 === 'BLOCKED_AUTH' || gate2 === 'BLOCKED_AUTH'
        ? 'BLOCKED_AUTH'
        : gate1 !== 'PASS' || gate2 !== 'PASS'
          ? 'NOT_RUN'
          : statusFromRequired(gate3Prerequisites);
  const gates = {
    'GATE-E7-01': gate1,
    'GATE-E7-02': gate2,
    'GATE-E7-03': gate3,
  };
  evidenceById.get('EVD-E7-55').status = gate1;
  evidenceById.get('EVD-E7-56').status = gate2;
  evidenceById.get('EVD-E7-57').status = gate3;

  const status = Object.values(gates).includes('FAIL')
    ? 'FAILED'
    : Object.values(gates).includes('BLOCKED_AUTH')
      ? 'BLOCKED_AUTH'
      : gate3 === 'PASS'
        ? 'VERIFIED'
        : 'IN_PROGRESS';
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'EVIDENCE_INDEX',
    status,
    entryGate,
    artifacts,
    evidence,
    gates,
    counts: { artifacts: artifacts.length, evidence: evidence.length, gates: 3 },
    catalogSha256: objectSha256({ artifacts: STAGE7_ARTIFACTS, evidence: STAGE7_EVIDENCE }),
    containsSensitiveData: false,
  };
};

export const validateStage7Index = (index) => {
  if (
    !exactKeys(index, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'entryGate',
      'artifacts',
      'evidence',
      'gates',
      'counts',
      'catalogSha256',
      'containsSensitiveData',
    ]) ||
    index.schemaVersion !== 1 ||
    index?.stage !== 7 ||
    index?.kind !== 'EVIDENCE_INDEX' ||
    index?.containsSensitiveData !== false ||
    !sameIds(
      index?.artifacts?.map((entry) => entry?.id),
      STAGE7_ARTIFACTS.map(({ id }) => id),
    ) ||
    !sameIds(
      index?.evidence?.map((entry) => entry?.id),
      STAGE7_EVIDENCE.map(({ id }) => id),
    ) ||
    index?.counts?.artifacts !== 20 ||
    index?.counts?.evidence !== 57 ||
    index?.counts?.gates !== 3 ||
    !exactKeys(index?.gates, ['GATE-E7-01', 'GATE-E7-02', 'GATE-E7-03']) ||
    !Object.values(index.gates).every((state) => GATE_STATES.includes(state)) ||
    index.catalogSha256 !== objectSha256({ artifacts: STAGE7_ARTIFACTS, evidence: STAGE7_EVIDENCE })
  ) {
    fail('E7_INDEX_CONTRACT_INVALID');
  }
  let expected;
  try {
    expected = createStage7Index({
      entryGate: index.entryGate,
      artifactStates: Object.fromEntries(index.artifacts.map(({ id, status }) => [id, status])),
      evidenceStates: Object.fromEntries(
        index.evidence
          .filter(({ id }) => !['EVD-E7-55', 'EVD-E7-56', 'EVD-E7-57'].includes(id))
          .map(({ id, status }) => [id, status]),
      ),
    });
  } catch {
    fail('E7_INDEX_CONTRACT_INVALID');
  }
  if (canonicalJson(index) !== canonicalJson(expected)) fail('E7_INDEX_CONTRACT_INVALID');
  return index;
};

export const validateLocalPreflight = (preflight) => {
  const decisions = [
    'NOT_READY',
    'READY_FOR_NON_MUTATING_PLAN',
    'READY_FOR_AUTHORIZED_EPHEMERAL_PREFLIGHT',
    'READY_FOR_BUILD_FREEZE',
    'READY_FOR_CLOUD_PREFLIGHT',
  ];
  if (
    !exactKeys(preflight, [
      'schemaVersion',
      'stage',
      'kind',
      'generatedAt',
      'candidate',
      'stage6',
      'authorization',
      'decision',
      'issues',
      'cloudChecks',
      'gates',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
    ]) ||
    preflight.schemaVersion !== 1 ||
    preflight.stage !== 7 ||
    preflight.kind !== 'LOCAL_PREFLIGHT' ||
    !isoUtc(preflight.generatedAt) ||
    !decisions.includes(preflight.decision) ||
    !Array.isArray(preflight.issues) ||
    new Set(preflight.issues).size !== preflight.issues.length ||
    !preflight.issues.every(
      (issue) => typeof issue === 'string' && /^E7_[A-Z0-9_]+$/u.test(issue),
    ) ||
    (preflight.decision === 'NOT_READY'
      ? preflight.issues.length === 0
      : preflight.issues.length > 0) ||
    !exactKeys(preflight.stage6, ['status', 'code', 'runId']) ||
    !['PASS', 'CONDITIONAL_GO', 'FAIL'].includes(preflight.stage6.status) ||
    typeof preflight.stage6?.code !== 'string' ||
    !/^E6_[A-Z0-9_]+$/u.test(preflight.stage6.code) ||
    !(
      preflight.stage6.runId === null ||
      (typeof preflight.stage6.runId === 'string' && RUN_ID.test(preflight.stage6.runId))
    ) ||
    !exactKeys(preflight.candidate, [
      'commitSha',
      'treeSha',
      'branch',
      'workingTree',
      'changedFiles',
    ]) ||
    !SHA.test(preflight.candidate.commitSha ?? '') ||
    !SHA.test(preflight.candidate.treeSha ?? '') ||
    typeof preflight.candidate.branch !== 'string' ||
    preflight.candidate.branch.length === 0 ||
    preflight.candidate.branch.length > 255 ||
    !['CLEAN', 'DIRTY'].includes(preflight.candidate.workingTree) ||
    !Number.isSafeInteger(preflight.candidate.changedFiles) ||
    preflight.candidate.changedFiles < 0 ||
    (preflight.candidate.workingTree === 'CLEAN'
      ? preflight.candidate.changedFiles !== 0
      : preflight.candidate.changedFiles === 0) ||
    !exactKeys(preflight.authorization, [
      'schemaVersion',
      'stage',
      'authorizationId',
      'authorizationScope',
      'environment',
      'accountSha256',
      'accountSuffix',
      'region',
      'roleSha256',
      'sessionMode',
      'window',
      'budget',
      'domain',
      'cleanup',
      'credentialReferenceSha256',
      'containsSensitiveData',
    ]) ||
    !AUTHORIZATION_SCOPES.includes(preflight.authorization?.authorizationScope) ||
    !SHA256.test(preflight.authorization.accountSha256 ?? '') ||
    !exactKeys(preflight.authorization.roleSha256, [
      'readRoleArn',
      'deployRoleArn',
      'rollbackRoleArn',
      'cleanupRoleArn',
      'baselineRoleArn',
    ]) ||
    !Object.values(preflight.authorization.roleSha256).every((digest) => SHA256.test(digest)) ||
    !Array.isArray(preflight.authorization.credentialReferenceSha256) ||
    !preflight.authorization.credentialReferenceSha256.every((digest) => SHA256.test(digest)) ||
    preflight.authorization.containsSensitiveData !== false ||
    !exactKeys(preflight.cloudChecks, [
      'callerIdentity',
      'accountAllowlist',
      'region',
      'roleTrust',
      'bootstrap',
      'quotas',
    ]) ||
    !Object.values(preflight.cloudChecks).every((status) => status === 'NOT_RUN') ||
    !exactKeys(preflight.gates, ['GATE-E7-01', 'GATE-E7-02', 'GATE-E7-03']) ||
    !Object.values(preflight.gates).every((status) => status === 'NOT_RUN') ||
    preflight.externalRequests !== 0 ||
    preflight.mutationsPerformed !== 0 ||
    preflight.containsSensitiveData !== false
  ) {
    fail('E7_PREFLIGHT_CONTRACT_INVALID');
  }
  if (
    (preflight.stage6.status === 'FAIL' && preflight.decision !== 'NOT_READY') ||
    (preflight.stage6.status !== 'FAIL' && preflight.stage6.runId === null) ||
    (preflight.decision === 'READY_FOR_NON_MUTATING_PLAN' &&
      preflight.authorization.authorizationScope !== 'NON_MUTATING_PLAN') ||
    (preflight.decision === 'READY_FOR_AUTHORIZED_EPHEMERAL_PREFLIGHT' &&
      (preflight.authorization.authorizationScope !== 'EPHEMERAL_PRERELEASE' ||
        preflight.stage6.status !== 'CONDITIONAL_GO')) ||
    (preflight.decision === 'READY_FOR_BUILD_FREEZE' &&
      (preflight.authorization.authorizationScope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
        preflight.stage6.status !== 'PASS')) ||
    (preflight.decision === 'READY_FOR_CLOUD_PREFLIGHT' &&
      (preflight.authorization.authorizationScope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
        preflight.stage6.status !== 'PASS'))
  ) {
    fail('E7_PREFLIGHT_DECISION_INVALID');
  }
  return preflight;
};

export const createStage7Plan = (preflight, { now = new Date() } = {}) => {
  validateLocalPreflight(preflight);
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) fail('E7_PLAN_TIMESTAMP_INVALID');
  const index = createStage7Index({ entryGate: preflight.stage6.status });
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_PLAN',
    generatedAt: now.toISOString(),
    candidate: preflight.candidate,
    entryDecision: preflight.decision,
    authorizationScope: preflight.authorization.authorizationScope,
    index,
    mutationsPlannedOnly: true,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
};

export const validateStage7ReportDocument = (source) => {
  if (
    typeof source !== 'string' ||
    !source.startsWith('# Etapa 7 — Release y despliegue\n') ||
    !source.includes('STAGE7_FINAL_AUTHORITY:release-manifest.json') ||
    !source.includes('STATUS_BY_STAGE7_MANIFEST')
  ) {
    fail('E7_REPORT_AUTHORITY_INVALID');
  }
  const headings = [...source.matchAll(/^## ([0-9]+)\. (.+)$/gmu)].map((match) => ({
    number: Number(match[1]),
    title: match[2],
  }));
  if (
    headings.length !== 33 ||
    headings.some(
      (heading, index) =>
        heading.number !== index + 1 || heading.title !== STAGE7_REPORT_HEADINGS[index],
    )
  ) {
    fail('E7_REPORT_SECTIONS_INVALID');
  }
  return true;
};

export const validateStage7EvidenceIndexDocument = (source) => {
  const artifactIds = source.match(/\bART-REL-[0-9]{2}\b/gu) ?? [];
  const evidenceIds = source.match(/\bEVD-E7-[0-9]{2}\b/gu) ?? [];
  if (
    !sameIds(
      artifactIds,
      STAGE7_ARTIFACTS.map(({ id }) => id),
    ) ||
    !sameIds(
      evidenceIds,
      STAGE7_EVIDENCE.map(({ id }) => id),
    ) ||
    !source.includes('STATUS_BY_STAGE7_MANIFEST')
  ) {
    fail('E7_INDEX_DOCUMENT_INVALID');
  }
  return true;
};

export const validateStage7Documents = ({ rootDirectory = workspaceRoot } = {}) => {
  validateStage7ReportDocument(
    readFileSync(
      path.resolve(rootDirectory, 'docs/verification/stage7-release-report.md'),
      'utf8',
    ).replace(/\r\n?/gu, '\n'),
  );
  validateStage7EvidenceIndexDocument(
    readFileSync(
      path.resolve(rootDirectory, 'docs/verification/stage7-evidence-index.md'),
      'utf8',
    ).replace(/\r\n?/gu, '\n'),
  );
  return true;
};

export const writeStage7Json = (target, label, value) => {
  const resolved = path.resolve(target);
  const relative = path.relative(workspaceRoot, resolved);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail('E7_OUTPUT_PATH_OUTSIDE_WORKSPACE');
  }
  return writeSanitizedJsonAtomic(resolved, label, value);
};

const validConfigFixture = ({ scope = 'FULL_RELEASE_VERSIONED_UPDATE' } = {}) => ({
  schemaVersion: 1,
  stage: 7,
  environment:
    scope === 'FULL_RELEASE_VERSIONED_UPDATE'
      ? 'assessment-release'
      : 'assessment-prerelease-e7-check',
  authorization: {
    id: 'AUTH-E7-RELEASE-01',
    status: 'APPROVED',
    scope,
    ownerAlias: 'release-owner',
    approvedAtUtc: '2026-08-17T10:00:00.000Z',
    expiresAtUtc: '2026-08-18T10:00:00.000Z',
    stacks: expectedStage7Stacks(
      scope === 'FULL_RELEASE_VERSIONED_UPDATE'
        ? 'assessment-release'
        : 'assessment-prerelease-e7-check',
    ),
    sandboxIncluded: scope !== 'NON_MUTATING_PLAN',
    destructiveActionsAllowed: false,
    communicationChannelAlias: 'release-channel',
    abortCriteria: ABORT_CRITERIA,
    rollbackOwnerAlias: 'rollback-owner',
  },
  aws: {
    accountId: '123456789012',
    region: 'us-east-1',
    roles: {
      readRoleArn: 'arn:aws:iam::123456789012:role/checkout-read',
      deployRoleArn: 'arn:aws:iam::123456789012:role/checkout-deploy',
      rollbackRoleArn: 'arn:aws:iam::123456789012:role/checkout-rollback',
      cleanupRoleArn: 'arn:aws:iam::123456789012:role/checkout-cleanup',
      baselineRoleArn: 'arn:aws:iam::123456789012:role/checkout-baseline',
    },
    sessionMode: 'OIDC',
  },
  window: {
    startsAtUtc: '2026-08-17T11:00:00.000Z',
    endsAtUtc: '2026-08-17T15:00:00.000Z',
  },
  budget: {
    maxUsd: 10,
    warningUsd: [5, 8],
    alertOwnerAlias: 'cost-owner',
    alertChannelAlias: 'cost-alerts',
    alertDestinationSha256: '3'.repeat(64),
  },
  domain:
    scope === 'FULL_RELEASE_VERSIONED_UPDATE'
      ? {
          mode: 'CUSTOM_AUTHORIZED',
          hostname: 'checkout.example.test',
          apiHostname: 'api.example.test',
          hostedZoneId: 'Z123456',
          webCertificateArn:
            'arn:aws:acm:us-east-1:123456789012:certificate/11111111-1111-1111-1111-111111111111',
          apiCertificateArn:
            'arn:aws:acm:us-east-1:123456789012:certificate/22222222-2222-2222-2222-222222222222',
          dnsIncluded: true,
        }
      : {
          mode: 'AWS_MANAGED',
          hostname: null,
          apiHostname: null,
          hostedZoneId: null,
          webCertificateArn: null,
          apiCertificateArn: null,
          dnsIncluded: false,
        },
  cleanup: {
    ownerAlias: 'cleanup-owner',
    expiresAtUtc:
      scope === 'EPHEMERAL_PRERELEASE' ? '2026-08-18T08:00:00.000Z' : '2026-08-20T15:00:00.000Z',
    preserveBootstrap: true,
    preservePreviousRelease: true,
  },
  prereleaseAccess:
    scope === 'EPHEMERAL_PRERELEASE'
      ? {
          mode: 'CLOUDFRONT_SIGNED_COOKIE',
          keyGroupId: 'K2STAGE7CHECKOUT',
          publicKeyId: 'K2STAGE7PUBLIC',
          originTokenSecretArn: [
            'arn:aws:secretsmanager:us-east-1:123456789012',
            ['sec', 'ret'].join(''),
            'checkout/runtime-security',
          ].join(':'),
          originTokenSecretVersionId: 'a'.repeat(32),
          rotationDuringWindow: 'FORBIDDEN',
        }
      : scope === 'FULL_RELEASE_VERSIONED_UPDATE'
        ? {
            mode: 'ORIGIN_GATE_ONLY',
            keyGroupId: null,
            publicKeyId: null,
            originTokenSecretArn: [
              'arn:aws:secretsmanager:us-east-1:123456789012',
              ['sec', 'ret'].join(''),
              'checkout/runtime-security',
            ].join(':'),
            originTokenSecretVersionId: 'a'.repeat(32),
            rotationDuringWindow: 'FORBIDDEN',
          }
        : {
            mode: 'NOT_APPLICABLE',
            keyGroupId: null,
            publicKeyId: null,
            originTokenSecretArn: null,
            originTokenSecretVersionId: null,
            rotationDuringWindow: 'NOT_APPLICABLE',
          },
  credentialReferences:
    scope === 'NON_MUTATING_PLAN'
      ? []
      : [
          [
            'arn:aws:secretsmanager:us-east-1:123456789012',
            ['sec', 'ret'].join(''),
            'checkout/runtime-security',
          ].join(':'),
        ],
  containsSensitiveData: false,
});

const e6Fixture = ({ status = 'PASS' } = {}) => ({
  schemaVersion: 1,
  stage: 6,
  artifactId: 'ART-VER-16',
  runId: 'e6-20260817t120000z-0123abcd',
  dataClassification: 'C0_SANITIZED_SUMMARY',
  containsSensitiveData: false,
  requiredDocumentsValid: true,
  externalRequestsMadeByCloseout: 0,
  candidate: {
    commitSha: 'a'.repeat(40),
    treeSha: 'b'.repeat(40),
    workingTree: 'CLEAN',
    changedFiles: 0,
  },
  status: status === 'PASS' ? 'RELEASE_CANDIDATE' : 'CONDITIONAL_GO_NOT_PUBLIC_RELEASE',
  releasePolicy: status === 'PASS' ? 'STAGE_7_FULL_ENABLED' : 'STAGE_7_NON_PUBLIC_PRERELEASE_ONLY',
  gates: {
    'GATE-E6-01': 'PASS',
    'GATE-E6-02': status === 'PASS' ? 'PASS' : 'CONDITIONAL_GO',
    'GATE-E6-03': status === 'PASS' ? 'PASS' : 'CONDITIONAL_GO',
  },
  artifactSummary: { total: 18, validStates: 18, failed: 0 },
  evidenceSummary:
    status === 'PASS'
      ? { total: 40, pass: 40, notRunAuth: 0, blocked: 0 }
      : { total: 40, pass: 37, notRunAuth: 3, blocked: 0 },
  artifacts: expectedIds('ART-VER', 18).map((id) => ({ id })),
  evidence: expectedIds('EVD-E6', 40).map((id) => ({ id })),
});

export const selfTestStage7 = () => {
  selfTestStrictJson();
  selfTestArtifactSanitizer();
  assert.equal(STAGE7_ARTIFACTS.length, 20);
  assert.equal(STAGE7_EVIDENCE.length, 57);
  assert.equal(STAGE7_AUDITS.length, 73);
  assert.equal(STAGE7_REPORT_HEADINGS.length, 33);

  const now = new Date('2026-08-17T12:00:00.000Z');
  const config = validConfigFixture();
  assert.equal(validateStage7Config(config, { now }), config);
  assert.throws(
    () =>
      validateStage7Config(
        {
          ...validConfigFixture({ scope: 'EPHEMERAL_PRERELEASE' }),
          environment: 'assessment-prerelease-slug-that-is-too-long',
        },
        { now },
      ),
    (error) => error instanceof Stage7Error && error.code === 'E7_CONFIG_ENVELOPE_INVALID',
  );
  const prereleaseCleanupBeyondAuthorization = validConfigFixture({
    scope: 'EPHEMERAL_PRERELEASE',
  });
  prereleaseCleanupBeyondAuthorization.cleanup = {
    ...prereleaseCleanupBeyondAuthorization.cleanup,
    expiresAtUtc: '2026-08-18T11:00:00.000Z',
  };
  assert.throws(
    () => validateStage7Config(prereleaseCleanupBeyondAuthorization, { now }),
    (error) =>
      error instanceof Stage7Error && error.code === 'E7_CLEANUP_AUTHORIZATION_WINDOW_INVALID',
  );
  const prereleaseCleanupWithoutRecoveryMargin = validConfigFixture({
    scope: 'EPHEMERAL_PRERELEASE',
  });
  prereleaseCleanupWithoutRecoveryMargin.cleanup = {
    ...prereleaseCleanupWithoutRecoveryMargin.cleanup,
    expiresAtUtc: '2026-08-18T08:00:00.001Z',
  };
  assert.throws(
    () => validateStage7Config(prereleaseCleanupWithoutRecoveryMargin, { now }),
    (error) =>
      error instanceof Stage7Error && error.code === 'E7_CLEANUP_AUTHORIZATION_WINDOW_INVALID',
  );
  const prereleaseAccess = validConfigFixture({ scope: 'EPHEMERAL_PRERELEASE' });
  for (const invalidAccess of [
    { ...prereleaseAccess.prereleaseAccess, mode: 'NOT_APPLICABLE' },
    { ...prereleaseAccess.prereleaseAccess, keyGroupId: null },
    { ...prereleaseAccess.prereleaseAccess, publicKeyId: null },
    { ...prereleaseAccess.prereleaseAccess, originTokenSecretArn: null },
    { ...prereleaseAccess.prereleaseAccess, enabled: true },
  ]) {
    assert.throws(
      () => validateStage7Config({ ...prereleaseAccess, prereleaseAccess: invalidAccess }, { now }),
      (error) =>
        error instanceof Stage7Error && error.code === 'E7_PRERELEASE_ACCESS_CONFIGURATION_INVALID',
    );
  }
  assert.throws(
    () =>
      validateStage7Config(
        {
          ...config,
          prereleaseAccess: validConfigFixture({ scope: 'EPHEMERAL_PRERELEASE' }).prereleaseAccess,
        },
        { now },
      ),
    (error) =>
      error instanceof Stage7Error && error.code === 'E7_PRERELEASE_ACCESS_CONFIGURATION_INVALID',
  );
  for (const invalidStacks of [
    config.authorization.stacks.slice(0, -1),
    [
      config.authorization.stacks[1],
      config.authorization.stacks[0],
      ...config.authorization.stacks.slice(2),
    ],
    [...config.authorization.stacks, 'checkout-assessment-release-extra'],
  ]) {
    assert.throws(
      () =>
        validateStage7Config(
          {
            ...config,
            authorization: { ...config.authorization, stacks: invalidStacks },
          },
          { now },
        ),
      (error) => error instanceof Stage7Error && error.code === 'E7_STACK_SCOPE_INVALID',
    );
  }
  assert.throws(
    () =>
      validateStage7Config(
        {
          ...config,
          authorization: { ...config.authorization, ownerAlias: 'owner@example.invalid' },
        },
        { now },
      ),
    (error) => error instanceof Stage7Error && error.code === 'E7_AUTHORIZATION_OWNER_INVALID',
  );
  assert.throws(
    () =>
      validateStage7Config(
        {
          ...config,
          credentialReferences: [['prv', 'test', 'unsafevalue123456'].join('_')],
        },
        { now },
      ),
    (error) => error instanceof Stage7Error && error.code === 'E7_CREDENTIAL_REFERENCES_INVALID',
  );
  assert.throws(
    () => validateStage7Config({ ...config, extra: true }, { now }),
    (error) => error instanceof Stage7Error && error.code === 'E7_CONFIG_ENVELOPE_INVALID',
  );
  assert.throws(
    () =>
      parseStrictJsonSource(
        Buffer.from(
          JSON.stringify({
            ...config,
            [['api', 'Key'].join('')]: ['unsafe', 'value', '1234567890'].join(''),
          }),
        ),
      ),
    (error) => error?.code === 'SOURCE_FORBIDDEN_DATA',
  );
  const wrongRole = {
    ...config,
    aws: {
      ...config.aws,
      roles: {
        ...config.aws.roles,
        deployRoleArn: 'arn:aws:iam::999999999999:role/checkout-release',
      },
    },
  };
  assert.throws(
    () => validateStage7Config(wrongRole, { now }),
    (error) => error instanceof Stage7Error && error.code === 'E7_DEPLOY_ROLE_INVALID',
  );
  assert.throws(
    () =>
      validateStage7Config(
        {
          ...config,
          aws: {
            ...config.aws,
            roles: {
              ...config.aws.roles,
              cleanupRoleArn: config.aws.roles.deployRoleArn,
            },
          },
        },
        { now },
      ),
    (error) => error instanceof Stage7Error && error.code === 'E7_AWS_ROLE_SEPARATION_INVALID',
  );
  assert.throws(
    () =>
      validateStage7Config(
        {
          ...config,
          domain: {
            mode: 'AWS_MANAGED',
            hostname: null,
            apiHostname: null,
            hostedZoneId: null,
            webCertificateArn: null,
            apiCertificateArn: null,
            dnsIncluded: false,
          },
        },
        { now },
      ),
    (error) =>
      error instanceof Stage7Error && error.code === 'E7_FULL_RELEASE_AUTHORIZATION_INCOMPLETE',
  );
  assert.equal(assessStage6Manifest(e6Fixture()).status, 'PASS');
  assert.equal(
    assessStage6Manifest(e6Fixture({ status: 'CONDITIONAL_GO' })).status,
    'CONDITIONAL_GO',
  );

  const temporary = mkdtempSync(path.join(os.tmpdir(), 'checkout-e7-self-test-'));
  try {
    writeFileSync(
      path.join(temporary, 'package.json'),
      JSON.stringify({ packageManager: 'pnpm@11.19.0' }),
    );
    writeFileSync(path.join(temporary, '.node-version'), process.version.slice(1));
    mkdirSync(path.join(temporary, 'infra'));
    writeFileSync(
      path.join(temporary, 'infra', 'package.json'),
      JSON.stringify({
        dependencies: { 'aws-cdk-lib': '2.265.0' },
        devDependencies: { 'aws-cdk': '2.1136.0' },
      }),
    );
    writeFileSync(path.join(temporary, 'web.bin'), 'web');
    writeFileSync(path.join(temporary, 'api.bin'), 'api');
    writeFileSync(path.join(temporary, 'worker.bin'), 'worker');
    writeFileSync(path.join(temporary, 'iac.json'), '{}');
    writeFileSync(path.join(temporary, 'lock.yaml'), 'lock');
    writeFileSync(path.join(temporary, 'openapi.yaml'), 'openapi: 3.1.2');
    writeFileSync(path.join(temporary, 'client.d.ts'), 'export {};');
    writeFileSync(path.join(temporary, 'public-config.json'), '{}');
    const configFilename = path.join(temporary, 'stage7-config.json');
    writeFileSync(configFilename, JSON.stringify(config));
    assert.equal(
      readStrictJsonFile(configFilename, {
        scanForbiddenData: true,
        validateConfig: true,
        now,
      }).aws.accountId,
      config.aws.accountId,
    );
    const firstHash = hashArtifactPath(path.join(temporary, 'web.bin'), {
      rootDirectory: temporary,
    });
    const secondHash = hashArtifactPath(path.join(temporary, 'web.bin'), {
      rootDirectory: temporary,
    });
    assert.deepEqual(firstHash, secondHash);

    const candidate = {
      commitSha: 'a'.repeat(40),
      treeSha: 'b'.repeat(40),
      branch: 'codex/stage-7',
      workingTree: 'CLEAN',
      changedFiles: 0,
    };
    // The freeze API reads the existing workspace toolchain; hashing is exercised against temp fixtures.
    const freezeBodyFixture = {
      schemaVersion: 1,
      stage: 7,
      kind: 'BUILD_ONCE_FREEZE',
      releaseId: 'rel-20260817-1100-aaaaaaa',
      candidateSha: candidate.commitSha,
      candidateTreeSha: candidate.treeSha,
      releaseTag: 'v0.1.0-rc.1',
      environment: config.environment,
      authorizationScope: config.authorization.scope,
      region: config.aws.region,
      sourceRunId: e6Fixture().runId,
      sourceArtifactId: '123456',
      sourceArtifactSha256: 'c'.repeat(64),
      preFreezeEvidenceSha256: 'e'.repeat(64),
      builtAt: '2026-08-17T11:00:00.000Z',
      configSha256: objectSha256(config),
      lockfileSha256: hashArtifactPath(path.join(temporary, 'lock.yaml'), {
        rootDirectory: temporary,
      }).sha256,
      openApiSha256: hashArtifactPath(path.join(temporary, 'openapi.yaml'), {
        rootDirectory: temporary,
      }).sha256,
      generatedClientSha256: hashArtifactPath(path.join(temporary, 'client.d.ts'), {
        rootDirectory: temporary,
      }).sha256,
      publicConfigSha256: hashArtifactPath(path.join(temporary, 'public-config.json'), {
        rootDirectory: temporary,
      }).sha256,
      stage6Gates: { ...e6Fixture().gates },
      toolchain: {
        node: process.version,
        packageManager: 'pnpm@11.19.0',
        cdkCli: '2.1136.0',
        cdkLibrary: '2.265.0',
        awsCli: '2.31.0',
      },
      artifacts: [
        ['web', 'web.bin'],
        ['api', 'api.bin'],
        ['worker', 'worker.bin'],
        ['iac', 'iac.json'],
      ].map(([name, filename]) => ({
        name,
        ...hashArtifactPath(path.join(temporary, filename), { rootDirectory: temporary }),
      })),
      controlInventory: {
        artifacts: {
          total: STAGE7_ARTIFACTS.length,
          idsSha256: objectSha256(STAGE7_ARTIFACTS.map(({ id }) => id)),
        },
        evidence: {
          total: STAGE7_EVIDENCE.length,
          idsSha256: objectSha256(STAGE7_EVIDENCE.map(({ id }) => id)),
        },
        audits: {
          total: STAGE7_AUDITS.length,
          idsSha256: objectSha256(STAGE7_AUDITS.map(({ id }) => id)),
        },
      },
      releaseMode: 'VERSIONED_UPDATE',
      updateReleaseSupported: true,
      updateReleaseUnsupportedReason: null,
      buildOnce: { immutable: true, rebuilt: false },
      containsSensitiveData: false,
    };
    freezeBodyFixture.templateSha256 = freezeBodyFixture.artifacts[3].sha256;
    const freeze = validateFreezeManifest({
      ...freezeBodyFixture,
      manifestSha256: objectSha256(freezeBodyFixture),
    });
    const createdFreeze = createFreezeManifest({
      config,
      e6Manifest: e6Fixture(),
      candidate,
      releaseTag: 'v0.1.0-rc.1',
      builtAt: '2026-08-17T11:00:00.000Z',
      sourceArtifactId: '123456',
      sourceArtifactSha256: 'c'.repeat(64),
      preFreezeEvidenceSha256: 'e'.repeat(64),
      awsCliVersion: '2.31.0',
      paths: {
        web: path.join(temporary, 'web.bin'),
        api: path.join(temporary, 'api.bin'),
        worker: path.join(temporary, 'worker.bin'),
        iac: path.join(temporary, 'iac.json'),
        lockfile: path.join(temporary, 'lock.yaml'),
        openapi: path.join(temporary, 'openapi.yaml'),
        generatedClient: path.join(temporary, 'client.d.ts'),
        publicConfig: path.join(temporary, 'public-config.json'),
      },
      rootDirectory: temporary,
    });
    assert.deepEqual(createdFreeze, freeze);

    const previousWebObjects = [
      ['index.html', 'web-old-index'],
      ['public-config.json', 'web-old-config'],
    ].map(([key, versionId], index) => ({
      key,
      versionId,
      etagSha256: String(index + 1).repeat(64),
      contentSha256: String(index + 4).repeat(64),
      bytes: index + 1,
    }));
    const previousManifest = createStage7PreviousReleaseManifest({
      schemaVersion: 1,
      stage: 7,
      kind: 'PREVIOUS_APPROVED_RELEASE',
      status: 'APPROVED_IMMUTABLE',
      capturedAtUtc: '2026-08-17T10:30:00.000Z',
      approvedAtUtc: '2026-08-17T10:00:00.000Z',
      environment: config.environment,
      region: config.aws.region,
      previous: {
        candidateSha: 'c'.repeat(40),
        candidateTreeSha: 'd'.repeat(40),
        releaseId: 'rel-20260816-1000-ccccccc',
        releaseTag: 'v0.0.9',
        configSha256: '1'.repeat(64),
        freezeManifestSha256: '2'.repeat(64),
        assemblySha256: '3'.repeat(64),
      },
      target: {
        candidateSha: freeze.candidateSha,
        candidateTreeSha: freeze.candidateTreeSha,
        releaseId: freeze.releaseId,
        releaseTag: freeze.releaseTag,
        configSha256: objectSha256(config),
        freezeManifestSha256: freeze.manifestSha256,
        assemblySha256: freeze.artifacts.find(({ name }) => name === 'iac').sha256,
      },
      resources: {
        api: {
          functionName: 'checkout-release-api',
          aliasName: 'live',
          version: '7',
          codeSha256: '4'.repeat(64),
        },
        worker: {
          functionName: 'checkout-release-worker',
          aliasName: 'live',
          version: '11',
          codeSha256: '5'.repeat(64),
        },
        web: {
          bucketName: 'checkout-release-web-123456789012',
          distributionId: 'EDFDVBD6EXAMPLE',
          objects: previousWebObjects,
          mutableInvalidationPaths: ['/index.html', '/public-config.json'],
        },
      },
      compatibility: {
        status: 'PASS',
        schemaStrategy: 'EXPAND_CONTRACT_N_AND_N_MINUS_1',
        dataRollback: 'FORBIDDEN_FORWARD_ONLY',
        apiContractEvidenceSha256: '6'.repeat(64),
        pendingReconciliationEvidenceSha256: '7'.repeat(64),
        smokeEvidenceSha256: '8'.repeat(64),
        smokeVerifiedAtUtc: '2026-08-17T10:15:00.000Z',
      },
      handoff: {
        sourceKind: 'BASELINE_BOOTSTRAP',
        sourceBundleSha256: 'b'.repeat(64),
        sourceArtifactProvenanceSha256: 'c'.repeat(64),
        targetCompatibilityEvidenceSha256: 'd'.repeat(64),
        finalDisableEvidenceSha256: 'e'.repeat(64),
        predecessorManifestSha256: null,
      },
      approval: {
        status: 'APPROVED',
        reviewerAlias: 'release-reviewer',
        approvalEvidenceSha256: '9'.repeat(64),
        releaseEvidenceSha256: 'a'.repeat(64),
      },
      containsSensitiveData: false,
    });
    assert.equal(
      validateStage7PreviousReleaseForTarget(previousManifest, {
        config,
        freezeManifest: freeze,
      }),
      previousManifest,
    );
    assert.throws(
      () =>
        validateStage7PreviousReleaseManifest({
          ...previousManifest,
          resources: {
            ...previousManifest.resources,
            api: { ...previousManifest.resources.api, version: '6' },
          },
        }),
      (error) =>
        error instanceof Stage7Error &&
        error.code === 'E7_PREVIOUS_RELEASE_MANIFEST_DIGEST_INVALID',
    );

    const candidateWebObjects = previousWebObjects.map((entry, index) => ({
      ...entry,
      versionId:
        entry.key === 'index.html' || entry.key === 'public-config.json'
          ? `${entry.versionId}-candidate`
          : entry.versionId,
      etagSha256: String(index + 2).repeat(64),
      contentSha256: String(index + 5).repeat(64),
    }));
    const candidateRecord = createStage7CandidateRollbackRecord({
      previousManifest,
      createdAtUtc: '2026-08-17T12:30:00.000Z',
      approvalSha256: 'b'.repeat(64),
      planSha256: 'c'.repeat(64),
      deploymentEvidenceSha256: 'd'.repeat(64),
      resources: {
        api: { ...previousManifest.resources.api, version: '8', codeSha256: 'e'.repeat(64) },
        worker: {
          ...previousManifest.resources.worker,
          version: '12',
          codeSha256: 'f'.repeat(64),
        },
        web: { ...previousManifest.resources.web, objects: candidateWebObjects },
      },
    });
    validateStage7CandidateRollbackRecord(candidateRecord, { previousManifest });
    assert.throws(
      () =>
        validateStage7CandidateRollbackRecord(
          { ...candidateRecord, approvalSha256: '0'.repeat(64) },
          { previousManifest, approvalSha256: candidateRecord.approvalSha256 },
        ),
      (error) =>
        error instanceof Stage7Error && error.code === 'E7_CANDIDATE_ROLLBACK_RECORD_INVALID',
    );

    const pendingState = {
      observedAtUtc: '2026-08-17T12:31:00.000Z',
      trackedCount: 2,
      oldestAgeSeconds: 45,
      snapshotSha256: '1'.repeat(64),
    };
    const observedState = (resources) => ({
      api: {
        functionName: resources.api.functionName,
        aliasName: resources.api.aliasName,
        version: resources.api.version,
      },
      worker: {
        functionName: resources.worker.functionName,
        aliasName: resources.worker.aliasName,
        version: resources.worker.version,
      },
      web: {
        bucketName: resources.web.bucketName,
        distributionId: resources.web.distributionId,
        objects: resources.web.objects.map(({ key, versionId, contentSha256 }) => ({
          key,
          versionId,
          contentSha256,
        })),
      },
      pending: pendingState,
      dataFactsSha256: '2'.repeat(64),
    });
    const rollbackPlan = createStage7VersionedRollbackPlan({
      direction: 'ROLLBACK_TO_PREVIOUS',
      previousManifest,
      candidateRecord,
      currentState: observedState(candidateRecord.resources),
    });
    assert.equal(rollbackPlan.decision, 'APPLY');
    assert.equal(rollbackPlan.aliases.api.toVersion, previousManifest.resources.api.version);
    const retryPlan = createStage7VersionedRollbackPlan({
      direction: 'ROLLBACK_TO_PREVIOUS',
      previousManifest,
      candidateRecord,
      currentState: observedState(previousManifest.resources),
    });
    assert.equal(retryPlan.decision, 'NOOP_ALREADY_APPLIED');
    const repromotionPlan = createStage7VersionedRollbackPlan({
      direction: 'REPROMOTE_CANDIDATE',
      previousManifest,
      candidateRecord,
      currentState: {
        ...observedState(previousManifest.resources),
        pending: {
          observedAtUtc: '2026-08-17T12:35:00.000Z',
          trackedCount: 0,
          oldestAgeSeconds: 0,
          snapshotSha256: '7'.repeat(64),
        },
      },
    });
    assert.equal(repromotionPlan.decision, 'APPLY');
    assert.equal(repromotionPlan.aliases.api.toVersion, candidateRecord.resources.api.version);
    const partialResumePlan = createStage7VersionedRollbackPlan({
      direction: 'ROLLBACK_TO_PREVIOUS',
      previousManifest,
      candidateRecord,
      currentState: {
        ...observedState(candidateRecord.resources),
        api: {
          functionName: candidateRecord.resources.api.functionName,
          aliasName: candidateRecord.resources.api.aliasName,
          version: previousManifest.resources.api.version,
        },
      },
    });
    assert.equal(partialResumePlan.decision, 'RESUME_PARTIAL');
    assert.equal(partialResumePlan.aliases.api.changed, false);
    assert.equal(partialResumePlan.aliases.worker.changed, true);
    assert.ok(partialResumePlan.web.objects.every(({ changed }) => changed));
    const emergencyRecoveryPlan = createStage7VersionedRollbackPlan({
      direction: 'ROLLBACK_TO_PREVIOUS',
      purpose: 'EMERGENCY_RECOVERY',
      previousManifest,
      candidateRecord,
      currentState: {
        ...observedState(candidateRecord.resources),
        pending: {
          observedAtUtc: '2026-08-17T12:31:00.000Z',
          trackedCount: 0,
          oldestAgeSeconds: 0,
          snapshotSha256: '8'.repeat(64),
        },
      },
    });
    assert.equal(emergencyRecoveryPlan.purpose, 'EMERGENCY_RECOVERY');
    assert.equal(emergencyRecoveryPlan.decision, 'APPLY');
    assert.throws(
      () =>
        createStage7VersionedRollbackPlan({
          direction: 'ROLLBACK_TO_PREVIOUS',
          previousManifest,
          candidateRecord,
          currentState: {
            ...observedState(candidateRecord.resources),
            worker: {
              functionName: candidateRecord.resources.worker.functionName,
              aliasName: candidateRecord.resources.worker.aliasName,
              version: '999',
            },
          },
        }),
      (error) =>
        error instanceof Stage7Error && error.code === 'E7_ROLLBACK_PARTIAL_OR_UNKNOWN_STATE',
    );

    const rollbackCheckpointBody = {
      schemaVersion: 1,
      stage: 7,
      kind: 'VERSIONED_ROLLBACK_CHECKPOINT',
      status: 'PASS',
      direction: rollbackPlan.direction,
      decision: 'APPLIED_AND_VERIFIED',
      scenarioIds: ['RB-E7-01', 'RB-E7-03', 'RB-E7-05', 'RB-E7-07'],
      planSha256: rollbackPlan.planSha256,
      startedAtUtc: '2026-08-17T12:32:00.000Z',
      completedAtUtc: '2026-08-17T12:34:00.000Z',
      fromReleaseId: rollbackPlan.fromReleaseId,
      toReleaseId: rollbackPlan.toReleaseId,
      aliases: {
        api: {
          functionName: previousManifest.resources.api.functionName,
          aliasName: previousManifest.resources.api.aliasName,
          version: previousManifest.resources.api.version,
        },
        worker: {
          functionName: previousManifest.resources.worker.functionName,
          aliasName: previousManifest.resources.worker.aliasName,
          version: previousManifest.resources.worker.version,
        },
      },
      web: {
        bucketName: previousManifest.resources.web.bucketName,
        distributionId: previousManifest.resources.web.distributionId,
        objects: previousManifest.resources.web.objects.map(
          ({ key, versionId, contentSha256, bytes }) => ({
            key,
            sourceVersionId: versionId,
            activeVersionId: `${versionId}-restored`,
            contentSha256,
            bytes,
          }),
        ),
        invalidation: {
          status: 'COMPLETED',
          idSha256: '3'.repeat(64),
          paths: [...previousManifest.resources.web.mutableInvalidationPaths],
        },
      },
      pendingIntegrity: {
        status: 'PASS',
        beforeSnapshotSha256: pendingState.snapshotSha256,
        afterSnapshotSha256: '4'.repeat(64),
        correlationEvidenceSha256: '5'.repeat(64),
        trackedBefore: 2,
        stillPending: 0,
        reconciled: 2,
        orphaned: 0,
        duplicateEffects: 0,
        lostFacts: 0,
      },
      dataFactsSha256: rollbackPlan.dataFactsSha256,
      dataFactsChanged: false,
      dataRollbackPerformed: false,
      stacksDeleted: 0,
      smoke: {
        status: 'PASS',
        releaseId: rollbackPlan.toReleaseId,
        evidenceSha256: '6'.repeat(64),
      },
      containsSensitiveData: false,
    };
    const rollbackCheckpoint = {
      ...rollbackCheckpointBody,
      checkpointSha256: objectSha256(rollbackCheckpointBody),
    };
    const rollbackTransition = createStage7VersionedRollbackTransition({
      plan: rollbackPlan,
      previousManifest,
      candidateRecord,
      startedAtUtc: rollbackCheckpoint.startedAtUtc,
      completedAtUtc: rollbackCheckpoint.completedAtUtc,
      aliases: rollbackCheckpoint.aliases,
      web: rollbackCheckpoint.web,
      pendingIntegrity: rollbackCheckpoint.pendingIntegrity,
    });
    assert.equal(
      validateStage7VersionedRollbackTransition(rollbackTransition, {
        plan: rollbackPlan,
        previousManifest,
        candidateRecord,
      }),
      rollbackTransition,
    );
    validateStage7VersionedRollbackCheckpoint(rollbackCheckpoint, {
      plan: rollbackPlan,
      previousManifest,
      candidateRecord,
    });
    const repromotionCheckpointBody = {
      ...rollbackCheckpointBody,
      direction: repromotionPlan.direction,
      scenarioIds: ['RB-E7-02', 'RB-E7-04', 'RB-E7-05', 'RB-E7-07'],
      planSha256: repromotionPlan.planSha256,
      startedAtUtc: '2026-08-17T12:35:00.000Z',
      completedAtUtc: '2026-08-17T12:37:00.000Z',
      fromReleaseId: repromotionPlan.fromReleaseId,
      toReleaseId: repromotionPlan.toReleaseId,
      aliases: {
        api: {
          functionName: candidateRecord.resources.api.functionName,
          aliasName: candidateRecord.resources.api.aliasName,
          version: candidateRecord.resources.api.version,
        },
        worker: {
          functionName: candidateRecord.resources.worker.functionName,
          aliasName: candidateRecord.resources.worker.aliasName,
          version: candidateRecord.resources.worker.version,
        },
      },
      web: {
        bucketName: candidateRecord.resources.web.bucketName,
        distributionId: candidateRecord.resources.web.distributionId,
        objects: candidateRecord.resources.web.objects.map(
          ({ key, versionId, contentSha256, bytes }) => ({
            key,
            sourceVersionId: versionId,
            activeVersionId: `${versionId}-repromoted`,
            contentSha256,
            bytes,
          }),
        ),
        invalidation: {
          status: 'COMPLETED',
          idSha256: '8'.repeat(64),
          paths: [...candidateRecord.resources.web.mutableInvalidationPaths],
        },
      },
      pendingIntegrity: {
        status: 'PASS',
        beforeSnapshotSha256: repromotionPlan.pendingBaseline.snapshotSha256,
        afterSnapshotSha256: '9'.repeat(64),
        correlationEvidenceSha256: 'a'.repeat(64),
        trackedBefore: 0,
        stillPending: 0,
        reconciled: 0,
        orphaned: 0,
        duplicateEffects: 0,
        lostFacts: 0,
      },
      dataFactsSha256: repromotionPlan.dataFactsSha256,
      smoke: {
        status: 'PASS',
        releaseId: repromotionPlan.toReleaseId,
        evidenceSha256: 'b'.repeat(64),
      },
    };
    const repromotionCheckpoint = {
      ...repromotionCheckpointBody,
      checkpointSha256: objectSha256(repromotionCheckpointBody),
    };
    validateStage7VersionedRollbackCheckpoint(repromotionCheckpoint, {
      plan: repromotionPlan,
      previousManifest,
      candidateRecord,
    });
    const rehearsal = createStage7VersionedRollbackRehearsal({
      previousManifest,
      candidateRecord,
      rollbackPlan,
      rollbackCheckpoint,
      repromotionPlan,
      repromotionCheckpoint,
    });
    assert.equal(
      validateStage7VersionedRollbackRehearsal(rehearsal, {
        previousManifest,
        candidateRecord,
      }),
      rehearsal,
    );
    assert.throws(
      () =>
        validateStage7VersionedRollbackRehearsal(
          { ...rehearsal, candidateRecordSha256: '0'.repeat(64) },
          { previousManifest, candidateRecord },
        ),
      (error) =>
        error instanceof Stage7Error && error.code === 'E7_VERSIONED_ROLLBACK_REHEARSAL_INVALID',
    );
    assert.throws(
      () =>
        validateStage7VersionedRollbackCheckpoint(
          {
            ...rollbackCheckpoint,
            pendingIntegrity: { ...rollbackCheckpoint.pendingIntegrity, orphaned: 1 },
          },
          { plan: rollbackPlan, previousManifest, candidateRecord },
        ),
      (error) =>
        error instanceof Stage7Error && error.code === 'E7_VERSIONED_ROLLBACK_CHECKPOINT_INVALID',
    );
    const ephemeralConfig = validConfigFixture({ scope: 'EPHEMERAL_PRERELEASE' });
    const ephemeralFreeze = createFreezeManifest({
      config: ephemeralConfig,
      e6Manifest: e6Fixture({ status: 'CONDITIONAL_GO' }),
      candidate,
      releaseTag: null,
      builtAt: '2026-08-17T11:00:00.000Z',
      sourceArtifactId: '123457',
      sourceArtifactSha256: 'd'.repeat(64),
      awsCliVersion: '2.31.0',
      paths: {
        web: path.join(temporary, 'web.bin'),
        api: path.join(temporary, 'api.bin'),
        worker: path.join(temporary, 'worker.bin'),
        iac: path.join(temporary, 'iac.json'),
        lockfile: path.join(temporary, 'lock.yaml'),
        openapi: path.join(temporary, 'openapi.yaml'),
        generatedClient: path.join(temporary, 'client.d.ts'),
        publicConfig: path.join(temporary, 'public-config.json'),
      },
      rootDirectory: temporary,
    });
    assert.equal(ephemeralFreeze.authorizationScope, 'EPHEMERAL_PRERELEASE');
    assert.equal(ephemeralFreeze.releaseTag, null);
    assert.equal(ephemeralFreeze.stage6Gates['GATE-E6-03'], 'CONDITIONAL_GO');
    assert.throws(
      () => validateFreezeManifest({ ...ephemeralFreeze, releaseTag: 'v0.1.0-rc.1' }),
      (error) => error instanceof Stage7Error && error.code === 'E7_FREEZE_SCOPE_GATE_INVALID',
    );
    assert.throws(
      () => validateFreezeManifest({ ...freeze, manifestSha256: '0'.repeat(64) }),
      (error) => error instanceof Stage7Error && error.code === 'E7_FREEZE_DIGEST_INVALID',
    );
    const preflight = createLocalPreflight({
      config,
      e6Manifest: e6Fixture(),
      freezeManifest: freeze,
      candidate,
      now,
    });
    assert.equal(preflight.decision, 'NOT_READY');
    assert.ok(preflight.issues.includes('E7_PREVIOUS_APPROVED_RELEASE_REQUIRED'));
    assert.equal(preflight.mutationsPerformed, 0);
    assert.deepEqual(Object.values(preflight.gates), ['NOT_RUN', 'NOT_RUN', 'NOT_RUN']);
    const versionedRollbackPreflight = createLocalPreflight({
      config,
      e6Manifest: e6Fixture(),
      freezeManifest: freeze,
      previousReleaseManifest: previousManifest,
      candidate,
      now,
    });
    assert.equal(versionedRollbackPreflight.decision, 'READY_FOR_CLOUD_PREFLIGHT');
    assert.deepEqual(versionedRollbackPreflight.issues, []);
    assert.equal(validateLocalPreflight(versionedRollbackPreflight), versionedRollbackPreflight);
    const tamperedRollbackPreflight = createLocalPreflight({
      config,
      e6Manifest: e6Fixture(),
      freezeManifest: freeze,
      previousReleaseManifest: {
        ...previousManifest,
        resources: {
          ...previousManifest.resources,
          api: { ...previousManifest.resources.api, version: '999' },
        },
      },
      candidate,
      now,
    });
    assert.equal(tamperedRollbackPreflight.decision, 'NOT_READY');
    assert.deepEqual(tamperedRollbackPreflight.issues, [
      'E7_PREVIOUS_RELEASE_MANIFEST_DIGEST_INVALID',
    ]);
    assert.equal(validateLocalPreflight(tamperedRollbackPreflight), tamperedRollbackPreflight);
    const beforeFreeze = createLocalPreflight({
      config,
      e6Manifest: e6Fixture(),
      candidate,
      now,
    });
    assert.equal(beforeFreeze.decision, 'READY_FOR_BUILD_FREEZE');
    assert.deepEqual(beforeFreeze.issues, []);
    assert.equal(validateLocalPreflight(beforeFreeze), beforeFreeze);
    const conditional = createLocalPreflight({
      config,
      e6Manifest: e6Fixture({ status: 'CONDITIONAL_GO' }),
      candidate,
      now,
    });
    assert.equal(conditional.decision, 'NOT_READY');
    assert.ok(conditional.issues.includes('E7_FULL_RELEASE_BLOCKED_BY_E6'));
    const ephemeral = createLocalPreflight({
      config: validConfigFixture({ scope: 'EPHEMERAL_PRERELEASE' }),
      e6Manifest: e6Fixture({ status: 'CONDITIONAL_GO' }),
      candidate,
      now,
    });
    assert.equal(ephemeral.decision, 'READY_FOR_AUTHORIZED_EPHEMERAL_PREFLIGHT');
    assert.deepEqual(ephemeral.issues, []);
    assert.equal(validateLocalPreflight(ephemeral), ephemeral);
    const outsideWindow = createLocalPreflight({
      config,
      e6Manifest: e6Fixture(),
      freezeManifest: freeze,
      candidate,
      now: new Date('2026-08-17T16:00:00.000Z'),
    });
    assert.equal(outsideWindow.decision, 'NOT_READY');
    assert.ok(outsideWindow.issues.includes('E7_OUTSIDE_RELEASE_WINDOW'));

    const allArtifacts = Object.fromEntries(STAGE7_ARTIFACTS.map(({ id }) => [id, 'VERIFIED']));
    const allEvidence = Object.fromEntries(
      STAGE7_EVIDENCE.slice(0, 54).map(({ id }) => [id, 'PASS']),
    );
    const completeIndex = createStage7Index({
      entryGate: 'PASS',
      artifactStates: allArtifacts,
      evidenceStates: allEvidence,
    });
    assert.equal(completeIndex.gates['GATE-E7-03'], 'PASS');
    assert.equal(validateStage7Index(completeIndex), completeIndex);
    const approvedNotApplicableIndex = createStage7Index({
      entryGate: 'PASS',
      artifactStates: { ...allArtifacts, 'ART-REL-01': 'NOT_APPLICABLE_APPROVED' },
      evidenceStates: { ...allEvidence, 'EVD-E7-01': 'NOT_APPLICABLE_APPROVED' },
    });
    assert.equal(approvedNotApplicableIndex.gates['GATE-E7-03'], 'PASS');
    const projectedAuthorityOnly = createStage7Index({
      entryGate: 'PASS',
      artifactStates: {
        'ART-REL-18': 'VERIFIED',
        'ART-REL-19': 'VERIFIED',
        'ART-REL-20': 'VERIFIED',
      },
      evidenceStates: allEvidence,
    });
    assert.equal(projectedAuthorityOnly.gates['GATE-E7-03'], 'NOT_RUN');
    assert.throws(
      () => validateStage7Index({ ...completeIndex, status: 'IN_PROGRESS' }),
      (error) => error instanceof Stage7Error && error.code === 'E7_INDEX_CONTRACT_INVALID',
    );
    const emptyIndex = createStage7Index({ entryGate: 'CONDITIONAL_GO' });
    assert.equal(emptyIndex.artifacts.length, 20);
    assert.equal(emptyIndex.evidence.length, 57);
    assert.equal(emptyIndex.gates['GATE-E7-03'], 'BLOCKED_AUTH');
    const notRunIndex = createStage7Index({ entryGate: 'NOT_RUN' });
    assert.equal(notRunIndex.status, 'IN_PROGRESS');
    assert.deepEqual(notRunIndex.gates, {
      'GATE-E7-01': 'NOT_RUN',
      'GATE-E7-02': 'NOT_RUN',
      'GATE-E7-03': 'NOT_RUN',
    });
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }

  validateStage7Documents();
  return true;
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const command = process.argv[2];
    if (command !== 'self-test' || process.argv.length !== 3) {
      fail('E7_CORE_COMMAND_INVALID');
    }
    selfTestStage7();
    process.stdout.write('{"status":"PASS","externalRequests":0,"mutationsPerformed":0}\n');
  } catch (error) {
    const code = error instanceof Stage7Error ? error.code : 'E7_CORE_SELF_TEST_UNEXPECTED';
    process.stderr.write(`stage-7 core: ${code}\n`);
    process.exitCode = 1;
  }
}
