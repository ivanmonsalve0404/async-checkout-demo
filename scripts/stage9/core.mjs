import { createHash } from 'node:crypto';

import {
  STAGE9_ACTION_AUTHORITY,
  STAGE9_ARTIFACTS,
  STAGE9_AUDIT_CONTROLS,
  STAGE9_AUTHORIZATIONS,
  STAGE9_EVIDENCE,
  STAGE9_GATES,
  STAGE9_REPORT_SECTIONS,
} from './catalog.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const RELEASE_TAG =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$/u;
const ACCEPTANCE_ID = /^acc-[a-z0-9][a-z0-9._-]{7,95}$/u;
const UTC = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3})?Z$/u;
const NOT_APPLICABLE = 'NOT_APPLICABLE';
const STAGE8_ARTIFACT_BINDINGS_SHA256 =
  'ada68a6d4724bc0172af4c2f18532c8f50490be8e91ac27dc68b0198e365a5db';
const stage8EvidenceIds = (...numbers) =>
  numbers.map((number) => `EVD-E8-${String(number).padStart(2, '0')}`);
export const STAGE8_ARTIFACT_EVIDENCE_BINDINGS = Object.freeze([
  { id: 'ART-ACC-01', material: 'EVIDENCE_SET', evidenceIds: stage8EvidenceIds(1, 2, 3) },
  {
    id: 'ART-ACC-02',
    material: 'EVIDENCE_SET',
    evidenceIds: stage8EvidenceIds(3, 4, 5, 10, 39),
  },
  { id: 'ART-ACC-03', material: 'EVIDENCE_SET', evidenceIds: stage8EvidenceIds(4, 5, 10, 11) },
  {
    id: 'ART-ACC-04',
    material: 'EVIDENCE_SET',
    evidenceIds: stage8EvidenceIds(5, 6, 7, 8, 9, 10),
  },
  {
    id: 'ART-ACC-05',
    material: 'EVIDENCE_SET',
    evidenceIds: stage8EvidenceIds(...Array.from({ length: 14 }, (_, index) => index + 11)),
  },
  {
    id: 'ART-ACC-06',
    material: 'EVIDENCE_SET',
    evidenceIds: stage8EvidenceIds(...Array.from({ length: 6 }, (_, index) => index + 25)),
  },
  {
    id: 'ART-ACC-07',
    material: 'EVIDENCE_SET',
    evidenceIds: stage8EvidenceIds(...Array.from({ length: 7 }, (_, index) => index + 31)),
  },
  { id: 'ART-ACC-08', material: 'EVIDENCE_SET', evidenceIds: stage8EvidenceIds(8, 38, 39, 40) },
  { id: 'ART-ACC-09', material: 'EVIDENCE_SET', evidenceIds: stage8EvidenceIds(41, 42, 43) },
  { id: 'ART-ACC-10', material: 'EVIDENCE_SET', evidenceIds: stage8EvidenceIds(44) },
  { id: 'ART-ACC-11', material: 'EVIDENCE_SET', evidenceIds: stage8EvidenceIds(45) },
  { id: 'ART-ACC-12', material: 'EVIDENCE_SET', evidenceIds: stage8EvidenceIds(46) },
  { id: 'ART-ACC-13', material: 'EVIDENCE_SET', evidenceIds: stage8EvidenceIds(11, 17, 46) },
  { id: 'ART-ACC-14', material: 'ASSESSMENT', evidenceIds: stage8EvidenceIds(47) },
  { id: 'ART-ACC-15', material: 'HANDOFF', evidenceIds: stage8EvidenceIds(48) },
  {
    id: 'ART-ACC-16',
    material: 'EVIDENCE_INDEX',
    evidenceIds: stage8EvidenceIds(...Array.from({ length: 48 }, (_, index) => index + 1)),
  },
]);
const FINAL_STATES = new Set(['CLOSED_RETAINED', 'CLOSED_DECOMMISSIONED']);
const NO_ROUTE_STATES = new Set([
  'NOT_STARTED',
  'INTERVIEW_HOLD',
  'BLOCKED_AUTH',
  'BLOCKED_EXTERNAL',
  'RETURN_TO_STAGE',
  'FAILED',
]);
const CHARTER_MODES = new Set([
  'NOT_SELECTED',
  'INTERVIEW_HOLD',
  'LIMITED_OBSERVATION',
  'FINAL_DECOMMISSION',
]);
const OPERATIONAL_MODES = new Set([
  'NOT_SELECTED',
  'INTERVIEW_HOLD',
  'LIMITED_OBSERVATION',
  'DEMO_ON_DEMAND',
  'FINAL_DECOMMISSION',
  'EVIDENCE_ONLY',
]);
const REQUESTED_STATES = new Set([...NO_ROUTE_STATES, ...FINAL_STATES]);
const ROUTES = new Set(['NONE', 'RETAINED', 'DECOMMISSIONED']);
const AUTHORIZATION_STATES = new Set(['APPROVED', 'PENDING', 'DENIED', 'DENIED_BY_DEFAULT']);
const ARTIFACT_RESULTS = new Set(['PRESENT', 'MISSING', 'NOT_EVALUATED']);
const EVIDENCE_RESULTS = new Set(['PRESENT', 'MISSING', 'NOT_EVALUATED']);
const CONTROL_RESULTS = new Set(['PASS', 'FAIL', 'ZERO', 'N-A', 'NOT_EVALUATED']);
const SECRET_KEY = /^(?:apiKey|cardNumber|cookie|cvc|cvv|pan|password|privateKey|secret|token)$/iu;
const SECRET_VALUE =
  /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:Basic|Bearer)\s+[A-Za-z0-9._~+/=-]{8,}|\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]{8,}|\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b)/u;

export class Stage9ContractError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage9ContractError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage9ContractError(code, cause === undefined ? undefined : { cause });
};

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const ensure = (condition, code) => {
  if (!condition) fail(code);
};
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const isUtc = (value) => {
  if (typeof value !== 'string' || !UTC.test(value) || Number.isNaN(Date.parse(value)))
    return false;
  const normalized = value.includes('.') ? value : `${value.slice(0, -1)}.000Z`;
  return new Date(value).toISOString() === normalized;
};
const isReference = (value) =>
  typeof value === 'string' &&
  value !== NOT_APPLICABLE &&
  /^[A-Za-z0-9][A-Za-z0-9_.:/-]{2,127}$/u.test(value);
const isAlias = (value) =>
  typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/u.test(value);
const isReferenceOrNa = (value) => value === NOT_APPLICABLE || isReference(value);
const isAliasOrNa = (value) => value === NOT_APPLICABLE || isAlias(value);
const isUtcOrNa = (value) => value === NOT_APPLICABLE || isUtc(value);

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
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');
export const objectSha256 = (value) => sha256(canonicalJson(value));

const validDocumentationPath = (value) =>
  value === 'README.md' ||
  (typeof value === 'string' &&
    /^docs\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\.md$/u.test(value) &&
    !value.includes('//') &&
    value.split('/').every((segment) => segment !== '.' && segment !== '..'));

const validReason = (value) =>
  typeof value === 'string' &&
  value.trim() === value &&
  value.length >= 12 &&
  value.length <= 500 &&
  [...value].every((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint > 31 && codePoint !== 127;
  });

const validateDocumentationCommit = (release) => {
  const documentation = release.documentationCommit;
  ensure(
    exactKeys(documentation, ['mode', 'authority']),
    'E9_INTAKE_DOCUMENTATION_AUTHORITY_INVALID',
  );
  if (release.runtimeSha === release.submissionSha) {
    ensure(
      documentation.mode === 'SAME_COMMIT' && documentation.authority === null,
      'E9_INTAKE_DOCUMENTATION_AUTHORITY_INVALID',
    );
    return;
  }
  const authority = documentation.authority;
  ensure(
    documentation.mode === 'DOCUMENTATION_ONLY_APPROVED' &&
      exactKeys(authority, [
        'schemaVersion',
        'stage',
        'kind',
        'status',
        'fromSha',
        'toSha',
        'changedPaths',
        'ownerAlias',
        'approvedByAlias',
        'approvedAtUtc',
        'reason',
        'sourceHashes',
        'containsSensitiveData',
        'authoritySha256',
        'authorityRawSha256',
      ]) &&
      authority.schemaVersion === 1 &&
      authority.stage === 8 &&
      authority.kind === 'STAGE8_DOCUMENTATION_COMMIT_AUTHORITY' &&
      authority.status === 'APPROVED' &&
      authority.fromSha === release.runtimeSha &&
      authority.toSha === release.submissionSha &&
      Array.isArray(authority.changedPaths) &&
      authority.changedPaths.length > 0 &&
      authority.changedPaths.length <= 128 &&
      new Set(authority.changedPaths).size === authority.changedPaths.length &&
      canonicalJson(authority.changedPaths) ===
        canonicalJson([...authority.changedPaths].toSorted()) &&
      authority.changedPaths.every(validDocumentationPath) &&
      isAlias(authority.ownerAlias) &&
      isAlias(authority.approvedByAlias) &&
      authority.ownerAlias !== authority.approvedByAlias &&
      isUtc(authority.approvedAtUtc) &&
      validReason(authority.reason) &&
      exactKeys(authority.sourceHashes, [
        'commitMetadataRawSha256',
        'changedPathsRawSha256',
        'approvalRawSha256',
        'updatedManifestRawSha256',
      ]) &&
      Object.values(authority.sourceHashes).every((digest) => SHA256.test(digest ?? '')) &&
      authority.containsSensitiveData === false &&
      SHA256.test(authority.authorityRawSha256 ?? ''),
    'E9_INTAKE_DOCUMENTATION_AUTHORITY_INVALID',
  );
  const { authorityRawSha256: ignoredRaw, authoritySha256, ...body } = authority;
  void ignoredRaw;
  ensure(
    SHA256.test(authoritySha256 ?? '') && authoritySha256 === objectSha256(body),
    'E9_INTAKE_DOCUMENTATION_AUTHORITY_SHA256_INVALID',
  );
};

const validEvidencePath = (value) =>
  typeof value === 'string' &&
  value.length >= 3 &&
  value.length <= 512 &&
  /^[A-Za-z0-9][A-Za-z0-9._/-]*$/u.test(value) &&
  !value.startsWith('stage8-finalization/') &&
  !value.includes('//') &&
  value.split('/').every((segment) => segment !== '.' && segment !== '..');

const validateStage8Finalization = (intake) => {
  ensure(
    objectSha256(STAGE8_ARTIFACT_EVIDENCE_BINDINGS) === STAGE8_ARTIFACT_BINDINGS_SHA256,
    'E9_INTAKE_ARTIFACT_BINDINGS_CONTRACT_INVALID',
  );
  const finalization = intake.finalization;
  ensure(
    exactKeys(finalization, ['draftRawSha256', 'draftSha256', 'authority']) &&
      SHA256.test(finalization.draftRawSha256 ?? '') &&
      SHA256.test(finalization.draftSha256 ?? ''),
    'E9_INTAKE_FINALIZATION_INVALID',
  );
  const authority = finalization.authority;
  ensure(
    exactKeys(authority, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'acceptanceId',
      'release',
      'provisionalSnapshotSha256',
      'sourceHashes',
      'assessmentSha256',
      'indexSha256',
      'packageSha256',
      'reportSha256',
      'handoffSha256',
      'evidenceInventorySha256',
      'artifactBindingsSha256',
      'artifactInventory',
      'artifactInventorySha256',
      'ownerAlias',
      'approvedByAlias',
      'approvedAtUtc',
      'reason',
      'containsSensitiveData',
      'authoritySha256',
      'authorityRawSha256',
    ]) &&
      authority.schemaVersion === 1 &&
      authority.stage === 8 &&
      authority.kind === 'STAGE8_ACCEPTANCE_FINALIZATION_AUTHORITY' &&
      authority.status === 'APPROVED' &&
      authority.acceptanceId === intake.acceptanceId &&
      canonicalJson(authority.release) === canonicalJson(intake.release) &&
      SHA256.test(authority.provisionalSnapshotSha256 ?? '') &&
      exactKeys(authority.sourceHashes, [
        'assessmentRawSha256',
        'indexRawSha256',
        'packageRawSha256',
        'reportRawSha256',
        'handoffRawSha256',
      ]) &&
      Object.values(authority.sourceHashes).every((digest) => SHA256.test(digest ?? '')) &&
      [
        'assessmentSha256',
        'indexSha256',
        'packageSha256',
        'reportSha256',
        'handoffSha256',
        'evidenceInventorySha256',
        'artifactBindingsSha256',
        'artifactInventorySha256',
        'authoritySha256',
        'authorityRawSha256',
      ].every((key) => SHA256.test(authority[key] ?? '')) &&
      authority.sourceHashes.indexRawSha256 === intake.package.indexRawSha256 &&
      authority.sourceHashes.packageRawSha256 === intake.package.rawSha256 &&
      authority.sourceHashes.reportRawSha256 === intake.report.rawSha256 &&
      authority.reportSha256 === intake.report.rawSha256 &&
      authority.sourceHashes.handoffRawSha256 === finalization.draftRawSha256 &&
      authority.handoffSha256 === finalization.draftSha256 &&
      authority.evidenceInventorySha256 === intake.package.evidenceInventorySha256 &&
      authority.artifactBindingsSha256 === STAGE8_ARTIFACT_BINDINGS_SHA256 &&
      authority.artifactBindingsSha256 === intake.package.artifactBindingsSha256 &&
      isAlias(authority.ownerAlias) &&
      isAlias(authority.approvedByAlias) &&
      authority.ownerAlias !== authority.approvedByAlias &&
      isUtc(authority.approvedAtUtc) &&
      Date.parse(authority.approvedAtUtc) >= Date.parse(intake.generatedAtUtc) &&
      validReason(authority.reason) &&
      authority.containsSensitiveData === false,
    'E9_INTAKE_FINALIZATION_AUTHORITY_INVALID',
  );
  const { authorityRawSha256: ignoredRaw, authoritySha256, ...authorityBody } = authority;
  void ignoredRaw;
  ensure(
    authoritySha256 === objectSha256(authorityBody),
    'E9_INTAKE_FINALIZATION_AUTHORITY_SHA256_INVALID',
  );
  ensure(
    Array.isArray(authority.artifactInventory) &&
      authority.artifactInventory.length === STAGE8_ARTIFACT_EVIDENCE_BINDINGS.length &&
      authority.artifactInventorySha256 === objectSha256(authority.artifactInventory),
    'E9_INTAKE_ARTIFACT_INVENTORY_INVALID',
  );
  const indexEntry = authority.artifactInventory.at(-1);
  ensure(
    Array.isArray(indexEntry?.sources) && indexEntry.sources.length === 49,
    'E9_INTAKE_ARTIFACT_INVENTORY_INVALID',
  );
  const evidenceSources = indexEntry.sources.slice(0, 48);
  ensure(
    evidenceSources.every(
      (source) =>
        exactKeys(source, ['path', 'rawSha256', 'bytes']) &&
        validEvidencePath(source.path) &&
        SHA256.test(source.rawSha256 ?? '') &&
        Number.isSafeInteger(source.bytes) &&
        source.bytes > 0 &&
        source.bytes <= 1024 * 1024,
    ) &&
      new Set(evidenceSources.map(({ path: sourcePath }) => sourcePath)).size === 48 &&
      evidenceSources.reduce((total, { bytes }) => total + bytes, 0) <= 16 * 1024 * 1024,
    'E9_INTAKE_EVIDENCE_INVENTORY_INVALID',
  );
  const evidenceById = new Map(
    stage8EvidenceIds(...Array.from({ length: 48 }, (_, index) => index + 1)).map((id, index) => [
      id,
      evidenceSources[index],
    ]),
  );
  for (let index = 0; index < STAGE8_ARTIFACT_EVIDENCE_BINDINGS.length; index += 1) {
    const expected = STAGE8_ARTIFACT_EVIDENCE_BINDINGS[index];
    const actual = authority.artifactInventory[index];
    const specialCount = expected.material === 'EVIDENCE_SET' ? 0 : 1;
    ensure(
      exactKeys(actual, ['id', 'material', 'evidenceIds', 'sources']) &&
        actual.id === expected.id &&
        actual.material === expected.material &&
        canonicalJson(actual.evidenceIds) === canonicalJson(expected.evidenceIds) &&
        Array.isArray(actual.sources) &&
        actual.sources.length === expected.evidenceIds.length + specialCount &&
        new Set(actual.sources.map(({ path: sourcePath }) => sourcePath)).size ===
          actual.sources.length &&
        expected.evidenceIds.every(
          (id, sourceIndex) =>
            canonicalJson(actual.sources[sourceIndex]) === canonicalJson(evidenceById.get(id)),
        ),
      'E9_INTAKE_ARTIFACT_INVENTORY_INVALID',
    );
  }
  const assessmentSource = authority.artifactInventory[13].sources.at(-1);
  const handoffSource = authority.artifactInventory[14].sources.at(-1);
  const indexSource = authority.artifactInventory[15].sources.at(-1);
  for (const [source, expectedPath, expectedRawSha256] of [
    [
      assessmentSource,
      'stage8-finalization/assessment.json',
      authority.sourceHashes.assessmentRawSha256,
    ],
    [handoffSource, 'stage8-finalization/handoff-draft.json', finalization.draftRawSha256],
    [indexSource, 'stage8-finalization/evidence-index.json', intake.package.indexRawSha256],
  ]) {
    ensure(
      exactKeys(source, ['path', 'rawSha256', 'bytes']) &&
        source.path === expectedPath &&
        source.rawSha256 === expectedRawSha256 &&
        Number.isSafeInteger(source.bytes) &&
        source.bytes > 0 &&
        source.bytes <= 16 * 1024 * 1024,
      'E9_INTAKE_ARTIFACT_INVENTORY_INVALID',
    );
  }
  const draftBody = {
    schemaVersion: intake.schemaVersion,
    schemaId: intake.schemaId,
    stage: intake.stage,
    kind: intake.kind,
    status: 'PENDING_FINAL_AUTHORITY',
    acceptanceId: intake.acceptanceId,
    generatedAtUtc: intake.generatedAtUtc,
    decision: 'ACCEPTED_PENDING_FINAL_AUTHORITY',
    release: intake.release,
    gates: { ...intake.gates, 'GATE-E8-03': 'BLOCKED_EXTERNAL' },
    urls: intake.urls,
    report: intake.report,
    package: intake.package,
    scorecard: intake.scorecard,
    quality: intake.quality,
    delivery: intake.delivery,
    acceptance: intake.acceptance,
    operation: intake.operation,
    containsSensitiveData: false,
  };
  const draft = { ...draftBody, handoffSha256: objectSha256(draftBody) };
  ensure(
    draft.handoffSha256 === finalization.draftSha256 &&
      sha256(`${JSON.stringify(draft, null, 2)}\n`) === finalization.draftRawSha256,
    'E9_INTAKE_FINALIZATION_DRAFT_BINDING_INVALID',
  );
};

const assertNoSecretMaterial = (value, path = '$') => {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoSecretMaterial(entry, `${path}[${index}]`));
    return;
  }
  if (!object(value)) {
    if (typeof value === 'string' && SECRET_VALUE.test(value)) {
      fail('E9_SOURCE_SECRET_MATERIAL_FORBIDDEN');
    }
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (SECRET_KEY.test(key)) fail('E9_SOURCE_SECRET_FIELD_FORBIDDEN');
    assertNoSecretMaterial(child, `${path}.${key}`);
  }
};

const parseHttps = (value, code) => {
  ensure(typeof value === 'string' && value.length <= 2048, code);
  let parsed;
  try {
    parsed = new URL(value);
  } catch (error) {
    fail(code, error);
  }
  ensure(
    parsed.protocol === 'https:' &&
      parsed.username === '' &&
      parsed.password === '' &&
      parsed.hash === '' &&
      parsed.hostname.length > 0,
    code,
  );
  return parsed;
};

const assertStage8HandoffShape = (intake) => {
  ensure(
    exactKeys(intake, [
      'schemaVersion',
      'schemaId',
      'stage',
      'kind',
      'status',
      'acceptanceId',
      'generatedAtUtc',
      'decision',
      'release',
      'gates',
      'urls',
      'report',
      'package',
      'scorecard',
      'quality',
      'delivery',
      'acceptance',
      'operation',
      'finalization',
      'containsSensitiveData',
      'handoffSha256',
    ]),
    'E9_INTAKE_SHAPE_INVALID',
  );
  ensure(
    ACCEPTANCE_ID.test(intake.acceptanceId ?? '') &&
      exactKeys(intake.release, [
        'releaseId',
        'runtimeSha',
        'submissionSha',
        'tag',
        'documentationCommit',
      ]) &&
      RELEASE_ID.test(intake.release.releaseId ?? '') &&
      SHA.test(intake.release.runtimeSha ?? '') &&
      SHA.test(intake.release.submissionSha ?? '') &&
      RELEASE_TAG.test(intake.release.tag ?? ''),
    'E9_INTAKE_RELEASE_INVALID',
  );
  ensure(
    exactKeys(intake.gates, ['GATE-E8-01', 'GATE-E8-02', 'GATE-E8-03']),
    'E9_INTAKE_GATES_INVALID',
  );
  ensure(
    exactKeys(intake.urls, ['application', 'api', 'docs', 'health', 'repository']),
    'E9_INTAKE_URL_SET_INVALID',
  );
  ensure(
    exactKeys(intake.report, ['filename', 'rawSha256']) &&
      intake.report.filename === 'etapa-8-aceptacion-evaluacion-final.md' &&
      SHA256.test(intake.report.rawSha256 ?? ''),
    'E9_INTAKE_REPORT_INVALID',
  );
  ensure(
    exactKeys(intake.package, [
      'rawSha256',
      'indexRawSha256',
      'evidenceInventorySha256',
      'artifactBindingsSha256',
      'artifacts',
      'evidence',
      'cases',
      'auditControls',
    ]) &&
      SHA256.test(intake.package.rawSha256 ?? '') &&
      SHA256.test(intake.package.indexRawSha256 ?? '') &&
      SHA256.test(intake.package.evidenceInventorySha256 ?? '') &&
      intake.package.artifactBindingsSha256 === STAGE8_ARTIFACT_BINDINGS_SHA256 &&
      intake.package.artifacts === 16 &&
      intake.package.evidence === 48 &&
      intake.package.cases === 32 &&
      intake.package.auditControls === 72,
    'E9_INTAKE_PACKAGE_INVALID',
  );
  ensure(
    exactKeys(intake.scorecard, [
      'baseVerifiedPoints',
      'baseTotalPoints',
      'bonusVerifiedPoints',
      'bonusTotalPoints',
      'highConfidenceBaseRubrics',
    ]) &&
      Number.isSafeInteger(intake.scorecard.bonusVerifiedPoints) &&
      intake.scorecard.bonusVerifiedPoints >= 0 &&
      intake.scorecard.bonusVerifiedPoints <= 50 &&
      intake.scorecard.bonusTotalPoints === 50,
    'E9_INTAKE_SCORECARD_INVALID',
  );
  ensure(
    exactKeys(intake.quality, [
      'openP0',
      'openP1',
      'openP2',
      'acceptedP2',
      'disqualifiers',
      'openCriticalRisks',
    ]) &&
      Number.isSafeInteger(intake.quality.openP2) &&
      intake.quality.openP2 >= 0 &&
      Number.isSafeInteger(intake.quality.acceptedP2) &&
      intake.quality.acceptedP2 >= 0,
    'E9_INTAKE_QUALITY_INVALID',
  );
  ensure(
    exactKeys(intake.delivery, ['repositoryPublic', 'readmeFinal']) &&
      exactKeys(intake.acceptance, ['defectsAccepted', 'risksAccepted', 'deviationsAccepted']),
    'E9_INTAKE_HANDOFF_COMPLETENESS_INVALID',
  );
  ensure(
    exactKeys(intake.operation, [
      'expiresAtUtc',
      'ownerAlias',
      'dashboardUrl',
      'alarmsStatus',
      'budget',
      'rollbackRunbook',
      'cleanupRunbook',
      'evidenceRetention',
      'pendingTransactions',
      'incident',
      'contacts',
      'closeWindow',
    ]) &&
      isAlias(intake.operation.ownerAlias) &&
      intake.operation.alarmsStatus === 'READY',
    'E9_INTAKE_OPERATION_SHAPE_INVALID',
  );
  ensure(
    exactKeys(intake.operation.budget, ['currency', 'amount', 'asOfUtc']) &&
      /^[A-Z]{3}$/u.test(intake.operation.budget.currency ?? '') &&
      typeof intake.operation.budget.amount === 'number' &&
      Number.isFinite(intake.operation.budget.amount) &&
      intake.operation.budget.amount >= 0,
    'E9_INTAKE_BUDGET_INVALID',
  );
  for (const key of ['rollbackRunbook', 'cleanupRunbook']) {
    ensure(
      exactKeys(intake.operation[key], ['url', 'sha256']) &&
        SHA256.test(intake.operation[key].sha256 ?? ''),
      'E9_INTAKE_RUNBOOK_INVALID',
    );
  }
  ensure(
    exactKeys(intake.operation.evidenceRetention, ['policyId', 'expiresAtUtc']) &&
      typeof intake.operation.evidenceRetention.policyId === 'string' &&
      intake.operation.evidenceRetention.policyId.length >= 3,
    'E9_INTAKE_RETENTION_INVALID',
  );
  ensure(
    exactKeys(intake.operation.pendingTransactions, ['status', 'count']) &&
      exactKeys(intake.operation.incident, ['status', 'id']) &&
      exactKeys(intake.operation.closeWindow, ['startsAtUtc', 'endsAtUtc']),
    'E9_INTAKE_OPERATION_NESTED_SHAPE_INVALID',
  );
};

const assertExactPublicUrls = (urls) => {
  const application = parseHttps(urls.application, 'E9_INTAKE_APPLICATION_URL_INVALID');
  const api = parseHttps(urls.api, 'E9_INTAKE_API_URL_INVALID');
  const docs = parseHttps(urls.docs, 'E9_INTAKE_DOCS_URL_INVALID');
  const health = parseHttps(urls.health, 'E9_INTAKE_HEALTH_URL_INVALID');
  const repository = parseHttps(urls.repository, 'E9_INTAKE_REPOSITORY_URL_INVALID');
  ensure(
    application.pathname === '/' && application.search === '',
    'E9_INTAKE_APPLICATION_URL_INVALID',
  );
  for (const [actual, expectedPath, code] of [
    [api, '/api', 'E9_INTAKE_API_URL_INVALID'],
    [docs, '/api/docs', 'E9_INTAKE_DOCS_URL_INVALID'],
    [health, '/api/health/ready', 'E9_INTAKE_HEALTH_URL_INVALID'],
  ]) {
    ensure(
      actual.origin === application.origin &&
        actual.pathname === expectedPath &&
        actual.search === '',
      code,
    );
  }
  ensure(
    repository.origin === 'https://github.com' &&
      repository.pathname === '/ivanmonsalve0404/async-checkout-demo' &&
      repository.search === '',
    'E9_INTAKE_REPOSITORY_URL_INVALID',
  );
};

export const validateStage8Intake = (intake) => {
  ensure(object(intake), 'E9_INTAKE_INVALID');
  assertNoSecretMaterial(intake);
  assertStage8HandoffShape(intake);
  ensure(intake.containsSensitiveData === false, 'E9_INTAKE_SENSITIVE_DATA_INVALID');
  validateDocumentationCommit(intake.release);
  validateStage8Finalization(intake);
  const { handoffSha256, ...handoffBody } = intake;
  ensure(
    SHA256.test(handoffSha256 ?? '') && objectSha256(handoffBody) === handoffSha256,
    'E9_INTAKE_HANDOFF_SHA256_INVALID',
  );
  ensure(
    intake.schemaId === 'async-checkout-stage8-acceptance-handoff' &&
      intake.schemaVersion === 1 &&
      intake.stage === 8 &&
      intake.kind === 'STAGE8_HANDOFF_TO_STAGE9',
    'E9_INTAKE_IDENTITY_INVALID',
  );
  ensure(
    intake.status === 'READY_FOR_STAGE9' && intake.decision === 'ACCEPTED',
    'E9_INTAKE_ACCEPTANCE_INVALID',
  );
  ensure(
    object(intake.gates) &&
      intake.gates['GATE-E8-01'] === 'PASS' &&
      intake.gates['GATE-E8-02'] === 'PASS' &&
      intake.gates['GATE-E8-03'] === 'PASS',
    'E9_INTAKE_GATES_INVALID',
  );
  ensure(isUtc(intake.generatedAtUtc), 'E9_INTAKE_GENERATED_AT_INVALID');
  assertExactPublicUrls(intake.urls);
  parseHttps(intake.operation.dashboardUrl, 'E9_INTAKE_DASHBOARD_URL_INVALID');
  parseHttps(intake.operation.rollbackRunbook.url, 'E9_INTAKE_ROLLBACK_RUNBOOK_INVALID');
  parseHttps(intake.operation.cleanupRunbook.url, 'E9_INTAKE_CLEANUP_RUNBOOK_INVALID');
  ensure(
    intake.quality.openP0 === 0 &&
      intake.quality.openP1 === 0 &&
      intake.quality.disqualifiers === 0 &&
      intake.quality.openCriticalRisks === 0 &&
      intake.quality.openP2 === intake.quality.acceptedP2,
    'E9_INTAKE_QUALITY_INVALID',
  );
  ensure(
    intake.scorecard.baseVerifiedPoints === 100 &&
      intake.scorecard.baseTotalPoints === 100 &&
      intake.scorecard.highConfidenceBaseRubrics === 6,
    'E9_INTAKE_SCORECARD_INVALID',
  );
  ensure(
    intake.delivery.repositoryPublic === true &&
      intake.delivery.readmeFinal === true &&
      intake.acceptance.defectsAccepted === true &&
      intake.acceptance.risksAccepted === true &&
      intake.acceptance.deviationsAccepted === true,
    'E9_INTAKE_HANDOFF_COMPLETENESS_INVALID',
  );
  ensure(
    intake.operation.pendingTransactions.status === 'INVENTORIED' &&
      Number.isSafeInteger(intake.operation.pendingTransactions.count) &&
      intake.operation.pendingTransactions.count >= 0,
    'E9_INTAKE_PENDING_INVALID',
  );
  ensure(
    (intake.operation.incident.status === 'NONE' && intake.operation.incident.id === null) ||
      (intake.operation.incident.status === 'OPEN' &&
        typeof intake.operation.incident.id === 'string' &&
        intake.operation.incident.id.length >= 3),
    'E9_INTAKE_INCIDENT_INVALID',
  );
  ensure(
    Array.isArray(intake.operation.contacts) &&
      new Set(intake.operation.contacts).size === intake.operation.contacts.length &&
      intake.operation.contacts.every(isAlias) &&
      intake.operation.contacts.includes(intake.operation.ownerAlias),
    'E9_INTAKE_CONTACTS_INVALID',
  );
  const generated = Date.parse(intake.generatedAtUtc);
  const starts = Date.parse(intake.operation.closeWindow.startsAtUtc);
  const ends = Date.parse(intake.operation.closeWindow.endsAtUtc);
  const expires = Date.parse(intake.operation.expiresAtUtc);
  const evidenceExpires = Date.parse(intake.operation.evidenceRetention.expiresAtUtc);
  ensure(
    [
      intake.operation.closeWindow.startsAtUtc,
      intake.operation.closeWindow.endsAtUtc,
      intake.operation.expiresAtUtc,
      intake.operation.evidenceRetention.expiresAtUtc,
      intake.operation.budget.asOfUtc,
    ].every(isUtc),
    'E9_INTAKE_TIME_INVALID',
  );
  ensure(
    generated <= starts && starts < ends && ends <= expires && ends <= evidenceExpires,
    'E9_INTAKE_WINDOW_INVALID',
  );
  return Object.freeze({
    acceptanceId: intake.acceptanceId,
    generatedAtUtc: intake.generatedAtUtc,
    release: Object.freeze({ ...intake.release }),
    urls: Object.freeze({ ...intake.urls }),
    reportSha256: intake.report.rawSha256,
    acceptancePackageSha256: intake.package.rawSha256,
    acceptanceEvidenceIndexSha256: intake.package.indexRawSha256,
    operationsOwner: intake.operation.ownerAlias,
    expiresAtUtc: intake.operation.expiresAtUtc,
    pendingCount: intake.operation.pendingTransactions.count,
  });
};

const unevaluatedGates = () =>
  Object.freeze(Object.fromEntries(STAGE9_GATES.map(({ id }) => [id, 'NOT_EVALUATED'])));

export const deriveStage9Entry = (intake, { intakeRawSha256 = NOT_APPLICABLE } = {}) => {
  try {
    ensure(SHA256.test(intakeRawSha256), 'E9_INTAKE_RAW_SHA256_INVALID');
    const validated = validateStage8Intake(intake);
    return Object.freeze({
      stage: 9,
      status: 'READY_FOR_AUTHORIZED_PREFLIGHT',
      decision: 'PREPARATION_ONLY',
      blocker: NOT_APPLICABLE,
      reasonCode: NOT_APPLICABLE,
      intakeRawSha256,
      acceptanceId: validated.acceptanceId,
      release: validated.release,
      gates: unevaluatedGates(),
      mutationAuthority: 'NONE',
      operationStarted: false,
      closureDeclared: false,
      containsSensitiveData: false,
    });
  } catch (error) {
    if (!(error instanceof Stage9ContractError)) throw error;
    return Object.freeze({
      stage: 9,
      status: 'NOT_READY',
      decision: 'NOT_READY',
      blocker: 'BLK-E9-01',
      reasonCode: error.code,
      intakeRawSha256: SHA256.test(intakeRawSha256) ? intakeRawSha256 : NOT_APPLICABLE,
      acceptanceId: NOT_APPLICABLE,
      release: Object.freeze({
        releaseId: NOT_APPLICABLE,
        runtimeSha: NOT_APPLICABLE,
        submissionSha: NOT_APPLICABLE,
        tag: NOT_APPLICABLE,
      }),
      gates: unevaluatedGates(),
      mutationAuthority: 'NONE',
      operationStarted: false,
      closureDeclared: false,
      containsSensitiveData: false,
    });
  }
};

const defaultAuthorizations = () =>
  STAGE9_AUTHORIZATIONS.map(({ id, defaultStatus }) => ({
    id,
    status: defaultStatus,
    authorityRef: NOT_APPLICABLE,
    approvedAtUtc: NOT_APPLICABLE,
  }));

export const createStage9PlanTemplate = ({ entryBindingSha256, plannedAtUtc }) => {
  ensure(SHA256.test(entryBindingSha256), 'E9_PLAN_ENTRY_BINDING_INVALID');
  ensure(isUtc(plannedAtUtc), 'E9_PLAN_TIME_INVALID');
  return {
    schemaId: 'async-checkout-stage9-local-closure-plan',
    schemaVersion: 1,
    stage: 9,
    kind: 'STAGE9_LOCAL_NON_OPERATIVE_PLAN',
    entryBindingSha256,
    plannedAtUtc,
    charterMode: 'NOT_SELECTED',
    operationalMode: 'NOT_SELECTED',
    requestedState: 'NOT_STARTED',
    route: 'NONE',
    authorizations: defaultAuthorizations(),
    action: {
      kind: 'NONE',
      authorizationId: NOT_APPLICABLE,
      rationaleSha256: NOT_APPLICABLE,
    },
    sandboxExecution: {
      mode: 'NOT_EXECUTED',
      authorizationId: NOT_APPLICABLE,
      rationaleSha256: NOT_APPLICABLE,
      evidenceIds: [],
      controlIds: [],
    },
    artifacts: STAGE9_ARTIFACTS.map(({ id }) => ({
      id,
      result: 'NOT_EVALUATED',
      rawSha256: NOT_APPLICABLE,
    })),
    evidence: STAGE9_EVIDENCE.map(({ id }) => ({
      id,
      result: 'NOT_EVALUATED',
      rawSha256: NOT_APPLICABLE,
    })),
    controls: STAGE9_AUDIT_CONTROLS.map(({ id }) => ({
      id,
      result: 'NOT_EVALUATED',
      reason: 'Pending authorized execution',
      approvalRef: NOT_APPLICABLE,
    })),
    retention: {
      ownerAlias: NOT_APPLICABLE,
      budgetId: NOT_APPLICABLE,
      expiresAtUtc: NOT_APPLICABLE,
      futureDecommissionPlanId: NOT_APPLICABLE,
    },
    decommission: {
      changeId: NOT_APPLICABLE,
      rehearsalStatus: 'NOT_EVALUATED',
      cleanupStatus: 'NOT_EVALUATED',
      residualResourceCount: -1,
      costResidualDocumented: false,
      accessTreated: false,
      dataTreated: false,
      evidencePreserved: false,
    },
    containsSensitiveData: false,
  };
};

const assertStage9PlanShape = (plan) => {
  ensure(
    exactKeys(plan, [
      'schemaId',
      'schemaVersion',
      'stage',
      'kind',
      'entryBindingSha256',
      'plannedAtUtc',
      'charterMode',
      'operationalMode',
      'requestedState',
      'route',
      'authorizations',
      'action',
      'sandboxExecution',
      'artifacts',
      'evidence',
      'controls',
      'retention',
      'decommission',
      'containsSensitiveData',
    ]) &&
      plan.schemaId === 'async-checkout-stage9-local-closure-plan' &&
      plan.schemaVersion === 1 &&
      plan.stage === 9 &&
      plan.kind === 'STAGE9_LOCAL_NON_OPERATIVE_PLAN' &&
      CHARTER_MODES.has(plan.charterMode) &&
      OPERATIONAL_MODES.has(plan.operationalMode) &&
      REQUESTED_STATES.has(plan.requestedState) &&
      ROUTES.has(plan.route),
    'E9_PLAN_SHAPE_INVALID',
  );
  ensure(
    exactKeys(plan.action, ['kind', 'authorizationId', 'rationaleSha256']),
    'E9_ACTION_SHAPE_INVALID',
  );
  ensure(
    exactKeys(plan.sandboxExecution, [
      'mode',
      'authorizationId',
      'rationaleSha256',
      'evidenceIds',
      'controlIds',
    ]) &&
      ['NOT_EXECUTED', 'READ_ONLY_VERIFICATION', 'MUTATING_SMOKE_OR_RECONCILIATION'].includes(
        plan.sandboxExecution.mode,
      ) &&
      Array.isArray(plan.sandboxExecution.evidenceIds) &&
      Array.isArray(plan.sandboxExecution.controlIds),
    'E9_PLAN_SANDBOX_EXECUTION_SHAPE_INVALID',
  );
  ensure(
    exactKeys(plan.retention, [
      'ownerAlias',
      'budgetId',
      'expiresAtUtc',
      'futureDecommissionPlanId',
    ]) &&
      isAliasOrNa(plan.retention.ownerAlias) &&
      isReferenceOrNa(plan.retention.budgetId) &&
      isUtcOrNa(plan.retention.expiresAtUtc) &&
      isReferenceOrNa(plan.retention.futureDecommissionPlanId),
    'E9_PLAN_RETENTION_SHAPE_INVALID',
  );
  ensure(
    exactKeys(plan.decommission, [
      'changeId',
      'rehearsalStatus',
      'cleanupStatus',
      'residualResourceCount',
      'costResidualDocumented',
      'accessTreated',
      'dataTreated',
      'evidencePreserved',
    ]) &&
      isReferenceOrNa(plan.decommission.changeId) &&
      ['PASS', 'FAIL', 'BLOCKED', 'NOT_EVALUATED'].includes(plan.decommission.rehearsalStatus) &&
      ['PASS', 'FAIL', 'BLOCKED', 'NOT_EVALUATED'].includes(plan.decommission.cleanupStatus) &&
      Number.isSafeInteger(plan.decommission.residualResourceCount) &&
      plan.decommission.residualResourceCount >= -1 &&
      [
        plan.decommission.costResidualDocumented,
        plan.decommission.accessTreated,
        plan.decommission.dataTreated,
        plan.decommission.evidencePreserved,
      ].every((value) => typeof value === 'boolean'),
    'E9_PLAN_DECOMMISSION_SHAPE_INVALID',
  );
};

const assertExactOrderedIds = (actual, expected, code) => {
  ensure(
    Array.isArray(actual) &&
      actual.length === expected.length &&
      actual.every((entry, index) => object(entry) && entry.id === expected[index].id),
    code,
  );
};

const validateAuthorizationRegistry = (authorizations) => {
  assertExactOrderedIds(authorizations, STAGE9_AUTHORIZATIONS, 'E9_PLAN_AUTHORIZATION_SET_INVALID');
  for (const authorization of authorizations) {
    ensure(
      exactKeys(authorization, ['id', 'status', 'authorityRef', 'approvedAtUtc']) &&
        AUTHORIZATION_STATES.has(authorization.status),
      'E9_PLAN_AUTHORIZATION_SHAPE_INVALID',
    );
    if (authorization.status === 'APPROVED') {
      ensure(
        isReference(authorization.authorityRef) && isUtc(authorization.approvedAtUtc),
        'E9_PLAN_AUTHORIZATION_APPROVAL_INVALID',
      );
    } else {
      ensure(
        authorization.authorityRef === NOT_APPLICABLE &&
          authorization.approvedAtUtc === NOT_APPLICABLE,
        'E9_PLAN_AUTHORIZATION_UNAPPROVED_METADATA_INVALID',
      );
    }
  }
  return new Map(authorizations.map((authorization) => [authorization.id, authorization]));
};

export const requireAuthorizedAction = (action, authorizations) => {
  ensure(
    exactKeys(action, ['kind', 'authorizationId', 'rationaleSha256']),
    'E9_ACTION_SHAPE_INVALID',
  );
  if (action.kind === 'NONE') {
    ensure(
      action.authorizationId === NOT_APPLICABLE && action.rationaleSha256 === NOT_APPLICABLE,
      'E9_ACTION_NONE_AUTHORITY_INVALID',
    );
    return Object.freeze({ kind: 'NONE', authorized: false, authorizationId: NOT_APPLICABLE });
  }
  const expectedAuthorization = STAGE9_ACTION_AUTHORITY[action.kind];
  ensure(expectedAuthorization !== undefined, 'E9_ACTION_KIND_INVALID');
  ensure(
    action.authorizationId === expectedAuthorization && SHA256.test(action.rationaleSha256),
    'E9_ACTION_AUTHORITY_BINDING_INVALID',
  );
  const registry = validateAuthorizationRegistry(authorizations);
  const authorization = registry.get(expectedAuthorization);
  ensure(authorization?.status === 'APPROVED', 'E9_ACTION_AUTHORITY_NOT_APPROVED');
  return Object.freeze({
    kind: action.kind,
    authorized: true,
    authorizationId: expectedAuthorization,
    authorityRef: authorization.authorityRef,
    approvedAtUtc: authorization.approvedAtUtc,
  });
};

const validateResultSet = ({ results, catalog, presentResult, allowedResults, code }) => {
  assertExactOrderedIds(results, catalog, code);
  for (const result of results) {
    ensure(
      exactKeys(result, ['id', 'result', 'rawSha256']) && allowedResults.has(result.result),
      code,
    );
    const hasBytes = result.result === presentResult;
    ensure(hasBytes ? SHA256.test(result.rawSha256) : result.rawSha256 === NOT_APPLICABLE, code);
  }
};

const validateControlResults = (controls, { requireFinal }) => {
  assertExactOrderedIds(controls, STAGE9_AUDIT_CONTROLS, 'E9_PLAN_CONTROL_SET_INVALID');
  for (let index = 0; index < controls.length; index += 1) {
    const result = controls[index];
    const contract = STAGE9_AUDIT_CONTROLS[index];
    ensure(
      exactKeys(result, ['id', 'result', 'reason', 'approvalRef']) &&
        CONTROL_RESULTS.has(result.result) &&
        typeof result.reason === 'string' &&
        /^[A-Za-z0-9][A-Za-z0-9 _.:/-]{2,255}$/u.test(result.reason) &&
        isReferenceOrNa(result.approvalRef),
      'E9_PLAN_CONTROL_RESULT_INVALID',
    );
    if (result.result === 'N-A') {
      ensure(contract.allowNotApplicable, 'E9_PLAN_CRITICAL_CONTROL_NA');
      ensure(
        result.reason !== NOT_APPLICABLE &&
          result.reason !== 'Pending authorized execution' &&
          isReference(result.approvalRef),
        'E9_PLAN_CONTROL_NA_JUSTIFICATION_INVALID',
      );
    }
    if (!requireFinal) continue;
    ensure(result.result !== 'NOT_EVALUATED' && result.result !== 'FAIL', 'E9_PLAN_CONTROL_OPEN');
    if (contract.expected === 'PASS')
      ensure(result.result === 'PASS', 'E9_PLAN_CONTROL_RESULT_INVALID');
    if (contract.expected === '0')
      ensure(result.result === 'ZERO', 'E9_PLAN_CONTROL_RESULT_INVALID');
    if (contract.expected === 'PASS/N-A') {
      ensure(['PASS', 'N-A'].includes(result.result), 'E9_PLAN_CONTROL_RESULT_INVALID');
    }
  }
};

const requireFinalPackage = (plan) => {
  ensure(
    plan.artifacts.every(({ result }) => result === 'PRESENT') &&
      plan.evidence.every(({ result }) => result === 'PRESENT'),
    'E9_PLAN_FINAL_PACKAGE_INCOMPLETE',
  );
  validateControlResults(plan.controls, { requireFinal: true });
};

const requireNaRetention = (retention) => {
  ensure(
    Object.values(retention).every((value) => value === NOT_APPLICABLE),
    'E9_PLAN_DECOMMISSION_RETENTION_CONFLICT',
  );
};

const requireRetainedRoute = (plan, authorizationRegistry) => {
  ensure(plan.route === 'RETAINED', 'E9_PLAN_RETAINED_ROUTE_INVALID');
  ensure(
    ['INTERVIEW_HOLD', 'LIMITED_OBSERVATION'].includes(plan.charterMode) &&
      ['INTERVIEW_HOLD', 'LIMITED_OBSERVATION', 'DEMO_ON_DEMAND'].includes(plan.operationalMode),
    'E9_PLAN_RETAINED_MODE_INVALID',
  );
  ensure(
    isAlias(plan.retention.ownerAlias) &&
      isReference(plan.retention.budgetId) &&
      isUtc(plan.retention.expiresAtUtc) &&
      isReference(plan.retention.futureDecommissionPlanId),
    'E9_PLAN_RETAINED_GOVERNANCE_INVALID',
  );
  ensure(plan.action.kind === 'NONE', 'E9_PLAN_RETAINED_MUTATION_CONFLICT');
  ensure(
    authorizationRegistry.get('AUTH-E9-ACCESS')?.status === 'APPROVED',
    'E9_PLAN_RETAINED_ACCESS_AUTHORITY_INCOMPLETE',
  );
  ensure(
    ['AUTH-E9-DESTROY', 'AUTH-E9-DATA'].every(
      (id) => authorizationRegistry.get(id)?.status !== 'APPROVED',
    ),
    'E9_PLAN_RETAINED_DESTRUCTIVE_AUTHORITY_CONFLICT',
  );
  const results = new Map(plan.controls.map(({ id, result }) => [id, result]));
  ensure(
    results.get('OPSAUD-39') === 'PASS' &&
      results.get('OPSAUD-49') === 'N-A' &&
      results.get('OPSAUD-50') === 'N-A' &&
      results.get('OPSAUD-51') === 'PASS',
    'E9_PLAN_RETAINED_AUDIT_ROUTE_INVALID',
  );
};

const requireDecommissionedRoute = (plan, actionAuthority, authorizationRegistry) => {
  ensure(plan.route === 'DECOMMISSIONED', 'E9_PLAN_DECOMMISSION_ROUTE_INVALID');
  ensure(
    plan.charterMode === 'FINAL_DECOMMISSION' &&
      ['FINAL_DECOMMISSION', 'EVIDENCE_ONLY'].includes(plan.operationalMode),
    'E9_PLAN_DECOMMISSION_MODE_INVALID',
  );
  ensure(
    actionAuthority.kind === 'DESTROY' &&
      plan.decommission.rehearsalStatus === 'PASS' &&
      plan.decommission.cleanupStatus === 'PASS' &&
      plan.decommission.residualResourceCount === 0 &&
      plan.decommission.costResidualDocumented === true &&
      plan.decommission.accessTreated === true &&
      plan.decommission.dataTreated === true &&
      plan.decommission.evidencePreserved === true &&
      isReference(plan.decommission.changeId),
    'E9_PLAN_DECOMMISSION_INCOMPLETE',
  );
  ensure(
    ['AUTH-E9-DESTROY', 'AUTH-E9-ACCESS', 'AUTH-E9-DATA'].every(
      (id) => authorizationRegistry.get(id)?.status === 'APPROVED',
    ),
    'E9_PLAN_DECOMMISSION_AUTHORITIES_INCOMPLETE',
  );
  requireNaRetention(plan.retention);
  const results = new Map(plan.controls.map(({ id, result }) => [id, result]));
  ensure(
    results.get('OPSAUD-39') === 'N-A' &&
      results.get('OPSAUD-49') === 'PASS' &&
      results.get('OPSAUD-50') === 'PASS' &&
      results.get('OPSAUD-51') === 'N-A',
    'E9_PLAN_DECOMMISSION_AUDIT_ROUTE_INVALID',
  );
};

const validateSandboxExecution = (plan, authorizationRegistry) => {
  const sandbox = plan.sandboxExecution;
  const authority = authorizationRegistry.get('AUTH-E9-SANDBOX');
  if (sandbox.mode === 'NOT_EXECUTED') {
    ensure(
      sandbox.authorizationId === NOT_APPLICABLE &&
        sandbox.rationaleSha256 === NOT_APPLICABLE &&
        sandbox.evidenceIds.length === 0 &&
        sandbox.controlIds.length === 0 &&
        !FINAL_STATES.has(plan.requestedState),
      'E9_PLAN_SANDBOX_EXECUTION_BINDING_INVALID',
    );
    return;
  }
  ensure(
    canonicalJson(sandbox.evidenceIds) === canonicalJson(['EVD-OPS-12', 'EVD-OPS-14']) &&
      canonicalJson(sandbox.controlIds) === canonicalJson(['OPSAUD-30']) &&
      plan.evidence.find(({ id }) => id === 'EVD-OPS-12')?.result === 'PRESENT' &&
      plan.evidence.find(({ id }) => id === 'EVD-OPS-14')?.result === 'PRESENT' &&
      plan.controls.find(({ id }) => id === 'OPSAUD-30')?.result === 'PASS',
    'E9_PLAN_SANDBOX_EXECUTION_BINDING_INVALID',
  );
  if (sandbox.mode === 'READ_ONLY_VERIFICATION') {
    ensure(
      sandbox.authorizationId === NOT_APPLICABLE &&
        sandbox.rationaleSha256 === NOT_APPLICABLE &&
        authority?.status === 'PENDING' &&
        plan.action.kind !== 'SANDBOX_RECONCILIATION',
      'E9_PLAN_SANDBOX_READ_ONLY_AUTHORITY_INVALID',
    );
    return;
  }
  ensure(
    sandbox.authorizationId === 'AUTH-E9-SANDBOX' &&
      SHA256.test(sandbox.rationaleSha256 ?? '') &&
      authority?.status === 'APPROVED',
    'E9_PLAN_SANDBOX_MUTATION_AUTHORITY_INCOMPLETE',
  );
};

const validateRoute = (plan, actionAuthority, authorizationRegistry) => {
  if (FINAL_STATES.has(plan.requestedState)) {
    ensure(
      authorizationRegistry.get('AUTH-E9-OBSERVE')?.status === 'APPROVED',
      'E9_PLAN_FINAL_OBSERVATION_AUTHORITY_INCOMPLETE',
    );
  }
  if (NO_ROUTE_STATES.has(plan.requestedState)) {
    ensure(plan.route === 'NONE', 'E9_PLAN_NON_FINAL_ROUTE_INVALID');
  }
  if (plan.requestedState === 'NOT_STARTED') {
    ensure(
      plan.charterMode === 'NOT_SELECTED' &&
        plan.operationalMode === 'NOT_SELECTED' &&
        plan.action.kind === 'NONE',
      'E9_PLAN_NOT_STARTED_CONFUSION',
    );
  }
  if (plan.requestedState === 'INTERVIEW_HOLD') {
    ensure(
      plan.charterMode === 'INTERVIEW_HOLD' && plan.operationalMode === 'INTERVIEW_HOLD',
      'E9_PLAN_HOLD_MODE_INVALID',
    );
  }
  if (plan.requestedState === 'CLOSED_RETAINED') {
    requireRetainedRoute(plan, authorizationRegistry);
  }
  if (plan.requestedState === 'CLOSED_DECOMMISSIONED') {
    requireDecommissionedRoute(plan, actionAuthority, authorizationRegistry);
  }
};

export const validateStage9Plan = (plan, { intakeRawSha256 }) => {
  ensure(object(plan), 'E9_PLAN_INVALID');
  assertNoSecretMaterial(plan);
  assertStage9PlanShape(plan);
  ensure(plan.containsSensitiveData === false, 'E9_PLAN_SENSITIVE_DATA_INVALID');
  ensure(
    plan.entryBindingSha256 === intakeRawSha256 && SHA256.test(intakeRawSha256),
    'E9_PLAN_ENTRY_BINDING_INVALID',
  );
  ensure(isUtc(plan.plannedAtUtc), 'E9_PLAN_TIME_INVALID');
  const registry = validateAuthorizationRegistry(plan.authorizations);
  let actionAuthority;
  try {
    actionAuthority = requireAuthorizedAction(plan.action, plan.authorizations);
  } catch (error) {
    if (
      error instanceof Stage9ContractError &&
      error.code === 'E9_ACTION_AUTHORITY_NOT_APPROVED' &&
      plan.requestedState === 'BLOCKED_AUTH'
    ) {
      actionAuthority = Object.freeze({
        kind: plan.action.kind,
        authorized: false,
        authorizationId: plan.action.authorizationId,
      });
    } else {
      throw error;
    }
  }
  validateResultSet({
    results: plan.artifacts,
    catalog: STAGE9_ARTIFACTS,
    presentResult: 'PRESENT',
    allowedResults: ARTIFACT_RESULTS,
    code: 'E9_PLAN_ARTIFACT_SET_INVALID',
  });
  validateResultSet({
    results: plan.evidence,
    catalog: STAGE9_EVIDENCE,
    presentResult: 'PRESENT',
    allowedResults: EVIDENCE_RESULTS,
    code: 'E9_PLAN_EVIDENCE_SET_INVALID',
  });
  validateControlResults(plan.controls, { requireFinal: FINAL_STATES.has(plan.requestedState) });
  validateSandboxExecution(plan, registry);
  validateRoute(plan, actionAuthority, registry);
  if (FINAL_STATES.has(plan.requestedState)) requireFinalPackage(plan);
  return Object.freeze({
    status: 'VALID_LOCAL_PLAN',
    requestedState: plan.requestedState,
    route: plan.route,
    finalClosureCandidate: FINAL_STATES.has(plan.requestedState),
    closureCandidateStructurallyComplete: FINAL_STATES.has(plan.requestedState),
    actionAuthorizationValidated: actionAuthority.authorized,
    authorizationStates: Object.freeze(
      Object.fromEntries([...registry].map(([id, authorization]) => [id, authorization.status])),
    ),
    gates: unevaluatedGates(),
    operationStarted: false,
    closureDeclared: false,
  });
};

export const stage9Catalog = () => ({
  schemaId: 'async-checkout-stage9-catalog',
  schemaVersion: 1,
  stage: 9,
  artifacts: STAGE9_ARTIFACTS,
  evidence: STAGE9_EVIDENCE,
  auditControls: STAGE9_AUDIT_CONTROLS,
  authorizations: STAGE9_AUTHORIZATIONS,
  actionAuthority: STAGE9_ACTION_AUTHORITY,
  gates: STAGE9_GATES,
  reportSections: STAGE9_REPORT_SECTIONS,
  containsSensitiveData: false,
});

export const stage9CatalogSha256 = () => objectSha256(stage9Catalog());

const table = (headers, rows) => [
  `| ${headers.join(' | ')} |`,
  `| ${headers.map(() => '---').join(' | ')} |`,
  ...rows.map((row) => `| ${row.join(' | ')} |`),
];

export const renderStage9CatalogMarkdown = () =>
  [
    '# Etapa 9 \u2014 Cat\u00e1logo contractual local',
    '',
    '<!-- STAGE9_LOCAL_PREPARATION_ONLY:NO_GATE_AUTHORITY -->',
    '',
    `- Cat\u00e1logo SHA-256: \`${stage9CatalogSha256()}\``,
    '- Autoridad operativa: `NONE`',
    '- Red/AWS/cleanup: `0`',
    '',
    '## Artefactos',
    '',
    ...table(
      ['ID', 'Nombre', 'Formato'],
      STAGE9_ARTIFACTS.map(({ id, name, format }) => [id, name, format]),
    ),
    '',
    '## Evidencias',
    '',
    ...table(
      ['ID', 'Nombre'],
      STAGE9_EVIDENCE.map(({ id, name }) => [id, name]),
    ),
    '',
    '## Auditor\u00eda',
    '',
    ...table(
      ['ID', 'Control', 'Esperado', 'N-A'],
      STAGE9_AUDIT_CONTROLS.map(({ id, name, expected, allowNotApplicable }) => [
        id,
        name,
        expected,
        allowNotApplicable ? 'S\u00ed, justificado y aprobado' : 'No',
      ]),
    ),
    '',
    '## Autorizaciones',
    '',
    ...table(
      ['ID', 'Acci\u00f3n', 'Requerida', 'Autoridad', 'Estado inicial'],
      STAGE9_AUTHORIZATIONS.map(({ id, action, requirement, authority, defaultStatus }) => [
        id,
        action,
        requirement,
        authority,
        defaultStatus,
      ]),
    ),
    '',
    '## Gates',
    '',
    ...table(
      ['ID', 'Nombre', 'Resultados permitidos'],
      STAGE9_GATES.map(({ id, name, allowedResults }) => [id, name, allowedResults.join(', ')]),
    ),
    '',
    ...STAGE9_GATES.flatMap(({ id, requirements, routes = [] }) => [
      `### ${id} \u2014 requisitos`,
      '',
      ...routes.flatMap(({ name, requirements: routeRequirements }) => [
        `- Ruta: ${name}`,
        ...routeRequirements.map((requirement) => `  - ${requirement}`),
      ]),
      ...requirements.map((requirement) => `- ${requirement}`),
      '',
    ]),
  ].join('\n');

export const renderStage9PreparationReport = (entry) => {
  const validEntry = entry.status === 'READY_FOR_AUTHORIZED_PREFLIGHT';
  const entryLines = validEntry
    ? [
        `- Estado local: \`${entry.status}\``,
        `- Acceptance ID: \`${entry.acceptanceId}\``,
        `- Release ID: \`${entry.release.releaseId}\``,
        `- Runtime SHA: \`${entry.release.runtimeSha}\``,
        `- Submission SHA: \`${entry.release.submissionSha}\``,
        `- Tag: \`${entry.release.tag}\``,
        `- Intake SHA-256: \`${entry.intakeRawSha256}\``,
      ]
    : [
        '- Estado local: `NOT_READY`',
        '- Bloqueo: `BLK-E9-01`',
        `- Raz\u00f3n: \`${entry.reasonCode}\``,
      ];
  const sections = STAGE9_REPORT_SECTIONS.flatMap((name, index) => {
    const number = index + 1;
    if (number === 1) return [`## ${number}. ${name}`, '', ...entryLines, ''];
    if (number === 2) {
      return [
        `## ${number}. ${name}`,
        '',
        validEntry
          ? '`E8_ACCEPTED_INPUT_VALIDATED_LOCALLY`; la operaci\u00f3n no ha comenzado.'
          : '`BLK-E9-01`; no iniciar, mutar ni cerrar.',
        '',
      ];
    }
    if (number >= 30 && number <= 32) {
      return [`## ${number}. ${name}`, '', '`NOT_EVALUATED`', ''];
    }
    return [`## ${number}. ${name}`, '', '`NOT_EVALUATED_BY_LOCAL_PREPARATION`', ''];
  });
  return [
    '# Etapa 9 \u2014 Operaci\u00f3n, observaci\u00f3n y cierre',
    '',
    '<!-- STAGE9_LOCAL_PREPARATION_ONLY:NO_GATE_AUTHORITY -->',
    '',
    '> Plantilla determinista. No demuestra operaci\u00f3n, observaci\u00f3n, mutaci\u00f3n, gate ni cierre.',
    '',
    ...sections,
  ].join('\n');
};
