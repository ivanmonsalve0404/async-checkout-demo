import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

import {
  STAGE9_ARTIFACTS,
  STAGE9_AUDIT_CONTROLS,
  STAGE9_AUTHORIZATIONS,
  STAGE9_EVIDENCE,
  STAGE9_GATES,
  STAGE9_REPORT_SECTIONS,
} from './catalog.mjs';
import {
  STAGE8_ARTIFACT_EVIDENCE_BINDINGS,
  Stage9ContractError,
  createStage9PlanTemplate,
  deriveStage9Entry,
  objectSha256,
  renderStage9PreparationReport,
  requireAuthorizedAction,
  sha256,
  stage9CatalogSha256,
  validateStage8Intake,
  validateStage9Plan,
} from './core.mjs';
import { selfTestStage9Documents } from './documents.mjs';
import {
  parseStage8IntakeSource,
  parseStage9PlanSource,
  selfTestStage9Schemas,
} from './schemas.mjs';

const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const SHA_C = 'c'.repeat(64);
const SHA_D = 'd'.repeat(64);
const SHA_E = 'e'.repeat(64);
const COMMIT_A = '1'.repeat(40);
const COMMIT_B = '2'.repeat(40);

const clone = (value) => JSON.parse(JSON.stringify(value));
const asSource = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
const stage9Error = (code) => (error) =>
  error instanceof Stage9ContractError && error.code === code;
const resignIntake = (value) => {
  const { handoffSha256: ignored, ...body } = value;
  void ignored;
  return { ...body, handoffSha256: objectSha256(body) };
};
const resignFinalization = (value) => {
  const authority = value.finalization.authority;
  const {
    authorityRawSha256: ignoredRaw,
    authoritySha256: ignoredCanonical,
    ...authorityBody
  } = authority;
  void ignoredRaw;
  void ignoredCanonical;
  const authorityWithSha = {
    ...authorityBody,
    authoritySha256: objectSha256(authorityBody),
  };
  value.finalization.authority = {
    ...authorityWithSha,
    authorityRawSha256: sha256(asSource(authorityWithSha)),
  };
  return resignIntake(value);
};
const resignHandoffChain = (value) => {
  const draftBody = {
    schemaVersion: value.schemaVersion,
    schemaId: value.schemaId,
    stage: value.stage,
    kind: value.kind,
    status: 'PENDING_FINAL_AUTHORITY',
    acceptanceId: value.acceptanceId,
    generatedAtUtc: value.generatedAtUtc,
    decision: 'ACCEPTED_PENDING_FINAL_AUTHORITY',
    release: value.release,
    gates: { ...value.gates, 'GATE-E8-03': 'BLOCKED_EXTERNAL' },
    urls: value.urls,
    report: value.report,
    package: value.package,
    scorecard: value.scorecard,
    quality: value.quality,
    delivery: value.delivery,
    acceptance: value.acceptance,
    operation: value.operation,
    containsSensitiveData: false,
  };
  const draft = { ...draftBody, handoffSha256: objectSha256(draftBody) };
  const draftSource = Buffer.from(`${JSON.stringify(draft, null, 2)}\n`, 'utf8');
  value.finalization.draftRawSha256 = sha256(draftSource);
  value.finalization.draftSha256 = draft.handoffSha256;
  value.finalization.authority.sourceHashes.handoffRawSha256 = sha256(draftSource);
  value.finalization.authority.handoffSha256 = draft.handoffSha256;
  const handoffSource = value.finalization.authority.artifactInventory[14].sources.at(-1);
  handoffSource.rawSha256 = sha256(draftSource);
  handoffSource.bytes = draftSource.length;
  value.finalization.authority.artifactInventorySha256 = objectSha256(
    value.finalization.authority.artifactInventory,
  );
  return resignFinalization(value);
};

export const createStage8IntakeFixture = ({
  submissionSha = COMMIT_A,
  changedPaths = ['README.md'],
} = {}) => {
  const documentationAuthorityBody = {
    schemaVersion: 1,
    stage: 8,
    kind: 'STAGE8_DOCUMENTATION_COMMIT_AUTHORITY',
    status: 'APPROVED',
    fromSha: COMMIT_A,
    toSha: submissionSha,
    changedPaths,
    ownerAlias: 'documentation-owner',
    approvedByAlias: 'documentation-approver',
    approvedAtUtc: '2026-08-18T11:59:00.000Z',
    reason: 'Documentation-only release metadata update reviewed and approved.',
    sourceHashes: {
      commitMetadataRawSha256: sha256('documentation-commit-metadata'),
      changedPathsRawSha256: sha256(JSON.stringify(changedPaths)),
      approvalRawSha256: sha256('documentation-approval'),
      updatedManifestRawSha256: sha256('updated-release-manifest'),
    },
    containsSensitiveData: false,
  };
  const documentationAuthorityWithSha = {
    ...documentationAuthorityBody,
    authoritySha256: objectSha256(documentationAuthorityBody),
  };
  const documentationCommit =
    submissionSha === COMMIT_A
      ? { mode: 'SAME_COMMIT', authority: null }
      : {
          mode: 'DOCUMENTATION_ONLY_APPROVED',
          authority: {
            ...documentationAuthorityWithSha,
            authorityRawSha256: sha256(asSource(documentationAuthorityWithSha)),
          },
        };
  const release = {
    releaseId: 'rel-20260818-1200-1a2b3c4',
    runtimeSha: COMMIT_A,
    submissionSha,
    tag: 'v1.0.0',
    documentationCommit,
  };
  const draftBody = {
    schemaVersion: 1,
    schemaId: 'async-checkout-stage8-acceptance-handoff',
    stage: 8,
    kind: 'STAGE8_HANDOFF_TO_STAGE9',
    status: 'PENDING_FINAL_AUTHORITY',
    acceptanceId: 'acc-20260818-stage8',
    generatedAtUtc: '2026-08-18T12:00:00.000Z',
    decision: 'ACCEPTED_PENDING_FINAL_AUTHORITY',
    release,
    gates: {
      'GATE-E8-01': 'PASS',
      'GATE-E8-02': 'PASS',
      'GATE-E8-03': 'BLOCKED_EXTERNAL',
    },
    urls: {
      application: 'https://checkout.example.com',
      api: 'https://checkout.example.com/api',
      docs: 'https://checkout.example.com/api/docs',
      health: 'https://checkout.example.com/api/health/ready',
      repository: 'https://github.com/ivanmonsalve0404/async-checkout-demo',
    },
    report: {
      filename: 'etapa-8-aceptacion-evaluacion-final.md',
      rawSha256: SHA_A,
    },
    package: {
      rawSha256: SHA_B,
      indexRawSha256: SHA_C,
      evidenceInventorySha256: sha256('stage8-evidence-inventory'),
      artifactBindingsSha256: 'ada68a6d4724bc0172af4c2f18532c8f50490be8e91ac27dc68b0198e365a5db',
      artifacts: 16,
      evidence: 48,
      cases: 32,
      auditControls: 72,
    },
    scorecard: {
      baseVerifiedPoints: 100,
      baseTotalPoints: 100,
      bonusVerifiedPoints: 0,
      bonusTotalPoints: 50,
      highConfidenceBaseRubrics: 6,
    },
    quality: {
      openP0: 0,
      openP1: 0,
      openP2: 1,
      acceptedP2: 1,
      disqualifiers: 0,
      openCriticalRisks: 0,
    },
    delivery: {
      repositoryPublic: true,
      readmeFinal: true,
    },
    acceptance: {
      defectsAccepted: true,
      risksAccepted: true,
      deviationsAccepted: true,
    },
    operation: {
      expiresAtUtc: '2026-08-21T12:00:00.000Z',
      ownerAlias: 'operations-owner',
      dashboardUrl: 'https://console.aws.amazon.com/cloudwatch/home',
      alarmsStatus: 'READY',
      budget: {
        currency: 'USD',
        amount: 10,
        asOfUtc: '2026-08-18T12:00:00.000Z',
      },
      rollbackRunbook: {
        url: 'https://github.com/ivanmonsalve0404/async-checkout-demo/blob/master/docs/rollback.md',
        sha256: SHA_D,
      },
      cleanupRunbook: {
        url: 'https://github.com/ivanmonsalve0404/async-checkout-demo/blob/master/docs/cleanup.md',
        sha256: SHA_E,
      },
      evidenceRetention: {
        policyId: 'RET-E9-01',
        expiresAtUtc: '2026-08-25T12:00:00.000Z',
      },
      pendingTransactions: { status: 'INVENTORIED', count: 0 },
      incident: { status: 'NONE', id: null },
      contacts: ['operations-owner', 'closure-owner'],
      closeWindow: {
        startsAtUtc: '2026-08-18T12:05:00.000Z',
        endsAtUtc: '2026-08-20T12:05:00.000Z',
      },
    },
    containsSensitiveData: false,
  };
  const draft = { ...draftBody, handoffSha256: objectSha256(draftBody) };
  const draftSource = Buffer.from(`${JSON.stringify(draft, null, 2)}\n`, 'utf8');
  const evidenceSources = Array.from({ length: 48 }, (_, index) => ({
    path: `evidence/evd-e8-${String(index + 1).padStart(2, '0')}.json`,
    rawSha256: sha256(`stage8-evidence-${index + 1}`),
    bytes: 100 + index,
  }));
  const evidenceById = new Map(
    evidenceSources.map((source, index) => [
      `EVD-E8-${String(index + 1).padStart(2, '0')}`,
      source,
    ]),
  );
  const assessmentRawSha256 = sha256('stage8-assessment-raw');
  const artifactInventory = STAGE8_ARTIFACT_EVIDENCE_BINDINGS.map((binding) => {
    const sources = binding.evidenceIds.map((id) => evidenceById.get(id));
    if (binding.material === 'ASSESSMENT') {
      sources.push({
        path: 'stage8-finalization/assessment.json',
        rawSha256: assessmentRawSha256,
        bytes: 2048,
      });
    }
    if (binding.material === 'HANDOFF') {
      sources.push({
        path: 'stage8-finalization/handoff-draft.json',
        rawSha256: sha256(draftSource),
        bytes: draftSource.length,
      });
    }
    if (binding.material === 'EVIDENCE_INDEX') {
      sources.push({
        path: 'stage8-finalization/evidence-index.json',
        rawSha256: SHA_C,
        bytes: 4096,
      });
    }
    return { ...binding, sources };
  });
  const authorityBody = {
    schemaVersion: 1,
    stage: 8,
    kind: 'STAGE8_ACCEPTANCE_FINALIZATION_AUTHORITY',
    status: 'APPROVED',
    acceptanceId: draftBody.acceptanceId,
    release,
    provisionalSnapshotSha256: sha256('stage8-provisional-snapshot'),
    sourceHashes: {
      assessmentRawSha256,
      indexRawSha256: SHA_C,
      packageRawSha256: SHA_B,
      reportRawSha256: SHA_A,
      handoffRawSha256: sha256(draftSource),
    },
    assessmentSha256: sha256('stage8-assessment-canonical'),
    indexSha256: sha256('stage8-index-canonical'),
    packageSha256: sha256('stage8-package-canonical'),
    reportSha256: SHA_A,
    handoffSha256: draft.handoffSha256,
    evidenceInventorySha256: draftBody.package.evidenceInventorySha256,
    artifactBindingsSha256: draftBody.package.artifactBindingsSha256,
    artifactInventory,
    artifactInventorySha256: objectSha256(artifactInventory),
    ownerAlias: 'acceptance-owner',
    approvedByAlias: 'acceptance-observer',
    approvedAtUtc: '2026-08-18T12:00:00.000Z',
    reason: 'Final acceptance approved after exact byte-level material verification.',
    containsSensitiveData: false,
  };
  const authorityWithSha = {
    ...authorityBody,
    authoritySha256: objectSha256(authorityBody),
  };
  const authority = {
    ...authorityWithSha,
    authorityRawSha256: sha256(asSource(authorityWithSha)),
  };
  const finalBody = {
    ...draftBody,
    status: 'READY_FOR_STAGE9',
    decision: 'ACCEPTED',
    gates: {
      'GATE-E8-01': 'PASS',
      'GATE-E8-02': 'PASS',
      'GATE-E8-03': 'PASS',
    },
    finalization: {
      draftRawSha256: sha256(draftSource),
      draftSha256: draft.handoffSha256,
      authority,
    },
  };
  return { ...finalBody, handoffSha256: objectSha256(finalBody) };
};

const approve = (plan, id) => {
  const authorization = plan.authorizations.find((entry) => entry.id === id);
  assert.notEqual(authorization, undefined);
  authorization.status = 'APPROVED';
  authorization.authorityRef = 'closure-approval';
  authorization.approvedAtUtc = '2026-08-18T12:01:00.000Z';
};

const fillFinalPackage = (plan) => {
  plan.artifacts = plan.artifacts.map((entry, index) => ({
    ...entry,
    result: 'PRESENT',
    rawSha256: index % 2 === 0 ? SHA_A : SHA_B,
  }));
  plan.evidence = plan.evidence.map((entry, index) => ({
    ...entry,
    result: 'PRESENT',
    rawSha256: index % 2 === 0 ? SHA_C : SHA_D,
  }));
  plan.controls = plan.controls.map((entry, index) => {
    const contract = STAGE9_AUDIT_CONTROLS[index];
    const result = contract.expected === '0' ? 'ZERO' : 'PASS';
    return {
      ...entry,
      result,
      reason: 'Verified by authorized executor',
      approvalRef: 'NOT_APPLICABLE',
    };
  });
};

const setNa = (plan, id) => {
  const control = plan.controls.find((entry) => entry.id === id);
  assert.notEqual(control, undefined);
  control.result = 'N-A';
  control.reason = 'Route does not execute this operation';
  control.approvalRef = 'closure-approval';
};

const retainedPlan = (binding) => {
  const plan = createStage9PlanTemplate({
    entryBindingSha256: binding,
    plannedAtUtc: '2026-08-18T12:01:00.000Z',
  });
  fillFinalPackage(plan);
  plan.charterMode = 'LIMITED_OBSERVATION';
  plan.operationalMode = 'LIMITED_OBSERVATION';
  plan.requestedState = 'CLOSED_RETAINED';
  plan.route = 'RETAINED';
  plan.sandboxExecution = {
    mode: 'READ_ONLY_VERIFICATION',
    authorizationId: 'NOT_APPLICABLE',
    rationaleSha256: 'NOT_APPLICABLE',
    evidenceIds: ['EVD-OPS-12', 'EVD-OPS-14'],
    controlIds: ['OPSAUD-30'],
  };
  approve(plan, 'AUTH-E9-OBSERVE');
  approve(plan, 'AUTH-E9-ACCESS');
  plan.retention = {
    ownerAlias: 'operations-owner',
    budgetId: 'BUDGET-E9-01',
    expiresAtUtc: '2026-08-21T12:00:00.000Z',
    futureDecommissionPlanId: 'DECOMMISSION-E9-01',
  };
  setNa(plan, 'OPSAUD-41');
  setNa(plan, 'OPSAUD-44');
  setNa(plan, 'OPSAUD-49');
  setNa(plan, 'OPSAUD-50');
  return plan;
};

const decommissionedPlan = (binding) => {
  const plan = createStage9PlanTemplate({
    entryBindingSha256: binding,
    plannedAtUtc: '2026-08-18T12:01:00.000Z',
  });
  fillFinalPackage(plan);
  plan.charterMode = 'FINAL_DECOMMISSION';
  plan.operationalMode = 'EVIDENCE_ONLY';
  plan.requestedState = 'CLOSED_DECOMMISSIONED';
  plan.route = 'DECOMMISSIONED';
  plan.sandboxExecution = {
    mode: 'READ_ONLY_VERIFICATION',
    authorizationId: 'NOT_APPLICABLE',
    rationaleSha256: 'NOT_APPLICABLE',
    evidenceIds: ['EVD-OPS-12', 'EVD-OPS-14'],
    controlIds: ['OPSAUD-30'],
  };
  approve(plan, 'AUTH-E9-OBSERVE');
  approve(plan, 'AUTH-E9-DESTROY');
  approve(plan, 'AUTH-E9-ACCESS');
  approve(plan, 'AUTH-E9-DATA');
  plan.action = {
    kind: 'DESTROY',
    authorizationId: 'AUTH-E9-DESTROY',
    rationaleSha256: SHA_E,
  };
  plan.decommission = {
    changeId: 'CHANGE-E9-01',
    rehearsalStatus: 'PASS',
    cleanupStatus: 'PASS',
    residualResourceCount: 0,
    costResidualDocumented: true,
    accessTreated: true,
    dataTreated: true,
    evidencePreserved: true,
  };
  setNa(plan, 'OPSAUD-39');
  setNa(plan, 'OPSAUD-41');
  setNa(plan, 'OPSAUD-51');
  return plan;
};

export const selfTestStage9 = () => {
  const schemaResult = selfTestStage9Schemas();
  const documentResult = selfTestStage9Documents();
  assert.equal(schemaResult.status, 'PASS');
  assert.equal(documentResult.status, 'PASS');
  assert.equal(STAGE9_ARTIFACTS.length, 18);
  assert.equal(STAGE9_EVIDENCE.length, 44);
  assert.equal(STAGE9_AUDIT_CONTROLS.length, 60);
  assert.equal(STAGE9_AUTHORIZATIONS.length, 7);
  assert.equal(STAGE9_GATES.length, 3);
  assert.equal(STAGE9_REPORT_SECTIONS.length, 34);
  assert.match(stage9CatalogSha256(), /^[0-9a-f]{64}$/u);

  const intake = createStage8IntakeFixture();
  const intakeSource = asSource(intake);
  const parsedIntake = parseStage8IntakeSource(intakeSource);
  assert.equal(parsedIntake.validated.acceptanceId, intake.acceptanceId);
  assert.equal(parsedIntake.rawSha256, sha256(intakeSource));
  assert.equal(validateStage8Intake(intake).pendingCount, 0);

  const documentaryIntake = createStage8IntakeFixture({ submissionSha: COMMIT_B });
  assert.equal(validateStage8Intake(documentaryIntake).pendingCount, 0);
  assert.equal(documentaryIntake.release.runtimeSha, COMMIT_A);
  assert.equal(documentaryIntake.release.submissionSha, COMMIT_B);

  const missingDocumentaryAuthority = clone(documentaryIntake);
  missingDocumentaryAuthority.release.documentationCommit = {
    mode: 'SAME_COMMIT',
    authority: null,
  };
  assert.throws(
    () => validateStage8Intake(resignIntake(missingDocumentaryAuthority)),
    stage9Error('E9_INTAKE_DOCUMENTATION_AUTHORITY_INVALID'),
  );

  const functionalDocumentaryChange = createStage8IntakeFixture({
    submissionSha: COMMIT_B,
    changedPaths: ['apps/api/src/main.ts'],
  });
  assert.throws(
    () => validateStage8Intake(functionalDocumentaryChange),
    stage9Error('E9_INTAKE_DOCUMENTATION_AUTHORITY_INVALID'),
  );

  const tamperedDocumentaryAuthority = clone(documentaryIntake);
  tamperedDocumentaryAuthority.release.documentationCommit.authority.reason =
    'Tampered documentation approval reason.';
  assert.throws(
    () => validateStage8Intake(resignIntake(tamperedDocumentaryAuthority)),
    stage9Error('E9_INTAKE_DOCUMENTATION_AUTHORITY_SHA256_INVALID'),
  );

  const handoffTamper = clone(intake);
  handoffTamper.release.releaseId = 'rel-20260818-1200-deadbee';
  assert.throws(
    () => parseStage8IntakeSource(asSource(handoffTamper)),
    stage9Error('E9_INTAKE_FINALIZATION_AUTHORITY_INVALID'),
  );

  const resignedArtifactSwap = clone(intake);
  resignedArtifactSwap.finalization.authority.artifactInventory[0].sources[0].rawSha256 = SHA_E;
  resignedArtifactSwap.finalization.authority.artifactInventorySha256 = objectSha256(
    resignedArtifactSwap.finalization.authority.artifactInventory,
  );
  assert.throws(
    () => validateStage8Intake(resignFinalization(resignedArtifactSwap)),
    stage9Error('E9_INTAKE_ARTIFACT_INVENTORY_INVALID'),
  );

  const resignedArbitraryDraft = clone(intake);
  resignedArbitraryDraft.finalization.draftSha256 = SHA_E;
  resignedArbitraryDraft.finalization.authority.handoffSha256 = SHA_E;
  assert.throws(
    () => validateStage8Intake(resignFinalization(resignedArbitraryDraft)),
    stage9Error('E9_INTAKE_FINALIZATION_DRAFT_BINDING_INVALID'),
  );

  const entry = deriveStage9Entry(intake, { intakeRawSha256: parsedIntake.rawSha256 });
  assert.equal(entry.status, 'READY_FOR_AUTHORIZED_PREFLIGHT');
  assert.equal(entry.operationStarted, false);
  assert.equal(entry.closureDeclared, false);
  assert.deepEqual(new Set(Object.values(entry.gates)), new Set(['NOT_EVALUATED']));

  const missing = clone(intake);
  delete missing.operation.cleanupRunbook;
  assert.throws(
    () => parseStage8IntakeSource(asSource(missing)),
    stage9Error('E9_INTAKE_SCHEMA_INVALID'),
  );

  const tamperedGate = clone(intake);
  tamperedGate.gates['GATE-E8-03'] = 'FAIL';
  assert.throws(
    () => parseStage8IntakeSource(asSource(tamperedGate)),
    stage9Error('E9_INTAKE_SCHEMA_INVALID'),
  );

  const rejected = clone(intake);
  rejected.decision = 'REJECTED';
  assert.throws(
    () => parseStage8IntakeSource(asSource(rejected)),
    stage9Error('E9_INTAKE_SCHEMA_INVALID'),
  );

  const wrongOrigin = clone(intake);
  wrongOrigin.urls.api = 'https://api.example.com/api';
  assert.throws(
    () => parseStage8IntakeSource(asSource(resignHandoffChain(wrongOrigin))),
    stage9Error('E9_INTAKE_API_URL_INVALID'),
  );

  const unacceptedP2 = clone(intake);
  unacceptedP2.quality.acceptedP2 = 0;
  assert.throws(
    () => parseStage8IntakeSource(asSource(resignHandoffChain(unacceptedP2))),
    stage9Error('E9_INTAKE_QUALITY_INVALID'),
  );

  const secret = clone(intake);
  secret.token = ['Bear', 'er abcdefghijklmnopqrstuvwxyz'].join('');
  assert.throws(
    () => validateStage8Intake(secret),
    stage9Error('E9_SOURCE_SECRET_FIELD_FORBIDDEN'),
  );

  assert.throws(
    () =>
      parseStage8IntakeSource(
        Buffer.from(
          '{"schemaId":"async-checkout-stage8-acceptance-handoff","schemaId":"tampered"}',
          'utf8',
        ),
      ),
    stage9Error('E9_INTAKE_SOURCE_INVALID'),
  );

  const notReady = deriveStage9Entry(tamperedGate, { intakeRawSha256: SHA_A });
  assert.equal(notReady.status, 'NOT_READY');
  assert.equal(notReady.blocker, 'BLK-E9-01');
  assert.equal(notReady.operationStarted, false);
  assert.deepEqual(new Set(Object.values(notReady.gates)), new Set(['NOT_EVALUATED']));

  const reportA = renderStage9PreparationReport(entry);
  const reportB = renderStage9PreparationReport(entry);
  assert.equal(reportA, reportB);
  assert.match(reportA, /STAGE9_LOCAL_PREPARATION_ONLY:NO_GATE_AUTHORITY/u);
  assert.match(reportA, /GATE-E9-03[\s\S]*`NOT_EVALUATED`/u);

  const template = createStage9PlanTemplate({
    entryBindingSha256: parsedIntake.rawSha256,
    plannedAtUtc: '2026-08-18T12:01:00.000Z',
  });
  const parsedTemplate = parseStage9PlanSource(asSource(template), {
    intakeRawSha256: parsedIntake.rawSha256,
  });
  assert.equal(parsedTemplate.validated.requestedState, 'NOT_STARTED');
  assert.equal(parsedTemplate.validated.closureDeclared, false);
  assert.equal(parsedTemplate.validated.actionAuthorizationValidated, false);

  const unknownState = clone(template);
  unknownState.requestedState = 'CLOSED_UNKNOWN';
  assert.throws(
    () =>
      validateStage9Plan(unknownState, {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_SHAPE_INVALID'),
  );

  const bindingTamper = clone(template);
  bindingTamper.entryBindingSha256 = SHA_E;
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(bindingTamper), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_ENTRY_BINDING_INVALID'),
  );

  const missingArtifact = clone(template);
  missingArtifact.artifacts.pop();
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(missingArtifact), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_SCHEMA_INVALID'),
  );

  const criticalNa = clone(template);
  criticalNa.controls[0] = {
    id: 'OPSAUD-01',
    result: 'N-A',
    reason: 'Improper attempt to skip entry authority',
    approvalRef: 'closure-approval',
  };
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(criticalNa), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_CRITICAL_CONTROL_NA'),
  );

  const holdConfusion = clone(template);
  holdConfusion.requestedState = 'INTERVIEW_HOLD';
  holdConfusion.route = 'RETAINED';
  holdConfusion.charterMode = 'INTERVIEW_HOLD';
  holdConfusion.operationalMode = 'INTERVIEW_HOLD';
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(holdConfusion), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_NON_FINAL_ROUTE_INVALID'),
  );

  const unauthorisedDestroy = clone(template);
  unauthorisedDestroy.action = {
    kind: 'DESTROY',
    authorizationId: 'AUTH-E9-DESTROY',
    rationaleSha256: SHA_A,
  };
  assert.throws(
    () => requireAuthorizedAction(unauthorisedDestroy.action, unauthorisedDestroy.authorizations),
    stage9Error('E9_ACTION_AUTHORITY_NOT_APPROVED'),
  );

  const wrongSeparateAuthority = clone(unauthorisedDestroy);
  approve(wrongSeparateAuthority, 'AUTH-E9-ARCHIVE');
  assert.throws(
    () =>
      requireAuthorizedAction(wrongSeparateAuthority.action, wrongSeparateAuthority.authorizations),
    stage9Error('E9_ACTION_AUTHORITY_NOT_APPROVED'),
  );

  const blocked = clone(unauthorisedDestroy);
  blocked.requestedState = 'BLOCKED_AUTH';
  const parsedBlocked = parseStage9PlanSource(asSource(blocked), {
    intakeRawSha256: parsedIntake.rawSha256,
  });
  assert.equal(parsedBlocked.validated.actionAuthorizationValidated, false);
  assert.equal(parsedBlocked.validated.closureDeclared, false);

  const retained = retainedPlan(parsedIntake.rawSha256);
  const retainedResult = parseStage9PlanSource(asSource(retained), {
    intakeRawSha256: parsedIntake.rawSha256,
  }).validated;
  assert.equal(retainedResult.finalClosureCandidate, true);
  assert.equal(retainedResult.route, 'RETAINED');
  assert.equal(retainedResult.gates['GATE-E9-03'], 'NOT_EVALUATED');
  assert.equal(retainedResult.closureDeclared, false);
  assert.deepEqual(
    ['AUTH-E9-SANDBOX', 'AUTH-E9-ARCHIVE', 'AUTH-E9-RESTORE'].map(
      (id) => retainedResult.authorizationStates[id],
    ),
    ['PENDING', 'DENIED_BY_DEFAULT', 'PENDING'],
  );

  const retainedWithoutSandboxCausality = clone(retained);
  retainedWithoutSandboxCausality.sandboxExecution = {
    mode: 'NOT_EXECUTED',
    authorizationId: 'NOT_APPLICABLE',
    rationaleSha256: 'NOT_APPLICABLE',
    evidenceIds: [],
    controlIds: [],
  };
  assert.throws(
    () =>
      validateStage9Plan(retainedWithoutSandboxCausality, {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_SANDBOX_EXECUTION_BINDING_INVALID'),
  );

  const retainedMutatingSandboxWithoutAuthority = clone(retained);
  retainedMutatingSandboxWithoutAuthority.sandboxExecution = {
    ...retainedMutatingSandboxWithoutAuthority.sandboxExecution,
    mode: 'MUTATING_SMOKE_OR_RECONCILIATION',
    authorizationId: 'AUTH-E9-SANDBOX',
    rationaleSha256: SHA_A,
  };
  assert.throws(
    () =>
      validateStage9Plan(retainedMutatingSandboxWithoutAuthority, {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_SANDBOX_MUTATION_AUTHORITY_INCOMPLETE'),
  );

  const retainedMutatingSandbox = clone(retainedMutatingSandboxWithoutAuthority);
  approve(retainedMutatingSandbox, 'AUTH-E9-SANDBOX');
  assert.equal(
    validateStage9Plan(retainedMutatingSandbox, {
      intakeRawSha256: parsedIntake.rawSha256,
    }).finalClosureCandidate,
    true,
  );

  const retainedReadOnlyWithSandboxAuthority = clone(retained);
  approve(retainedReadOnlyWithSandboxAuthority, 'AUTH-E9-SANDBOX');
  assert.throws(
    () =>
      validateStage9Plan(retainedReadOnlyWithSandboxAuthority, {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_SANDBOX_READ_ONLY_AUTHORITY_INVALID'),
  );

  const retainedWithoutObservationAuthority = clone(retained);
  Object.assign(
    retainedWithoutObservationAuthority.authorizations.find(({ id }) => id === 'AUTH-E9-OBSERVE'),
    {
      status: 'PENDING',
      authorityRef: 'NOT_APPLICABLE',
      approvedAtUtc: 'NOT_APPLICABLE',
    },
  );
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(retainedWithoutObservationAuthority), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_FINAL_OBSERVATION_AUTHORITY_INCOMPLETE'),
  );

  const retainedWithoutAccessAuthority = clone(retained);
  Object.assign(
    retainedWithoutAccessAuthority.authorizations.find(({ id }) => id === 'AUTH-E9-ACCESS'),
    {
      status: 'PENDING',
      authorityRef: 'NOT_APPLICABLE',
      approvedAtUtc: 'NOT_APPLICABLE',
    },
  );
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(retainedWithoutAccessAuthority), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_RETAINED_ACCESS_AUTHORITY_INCOMPLETE'),
  );

  const retainedWithDestroyAuthority = clone(retained);
  approve(retainedWithDestroyAuthority, 'AUTH-E9-DESTROY');
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(retainedWithDestroyAuthority), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_RETAINED_DESTRUCTIVE_AUTHORITY_CONFLICT'),
  );

  const retainedWithDataAuthority = clone(retained);
  approve(retainedWithDataAuthority, 'AUTH-E9-DATA');
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(retainedWithDataAuthority), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_RETAINED_DESTRUCTIVE_AUTHORITY_CONFLICT'),
  );

  const decommissioned = decommissionedPlan(parsedIntake.rawSha256);
  const decommissionedResult = parseStage9PlanSource(asSource(decommissioned), {
    intakeRawSha256: parsedIntake.rawSha256,
  }).validated;
  assert.equal(decommissionedResult.finalClosureCandidate, true);
  assert.equal(decommissionedResult.route, 'DECOMMISSIONED');
  assert.equal(decommissionedResult.actionAuthorizationValidated, true);
  assert.equal(decommissionedResult.gates['GATE-E9-03'], 'NOT_EVALUATED');
  assert.equal(decommissionedResult.closureDeclared, false);
  assert.deepEqual(
    ['AUTH-E9-SANDBOX', 'AUTH-E9-ARCHIVE', 'AUTH-E9-RESTORE'].map(
      (id) => decommissionedResult.authorizationStates[id],
    ),
    ['PENDING', 'DENIED_BY_DEFAULT', 'PENDING'],
  );

  const decommissionedWithoutObservationAuthority = clone(decommissioned);
  Object.assign(
    decommissionedWithoutObservationAuthority.authorizations.find(
      ({ id }) => id === 'AUTH-E9-OBSERVE',
    ),
    {
      status: 'PENDING',
      authorityRef: 'NOT_APPLICABLE',
      approvedAtUtc: 'NOT_APPLICABLE',
    },
  );
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(decommissionedWithoutObservationAuthority), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_FINAL_OBSERVATION_AUTHORITY_INCOMPLETE'),
  );

  const missingAccessAuthority = clone(decommissioned);
  Object.assign(
    missingAccessAuthority.authorizations.find(({ id }) => id === 'AUTH-E9-ACCESS'),
    {
      status: 'PENDING',
      authorityRef: 'NOT_APPLICABLE',
      approvedAtUtc: 'NOT_APPLICABLE',
    },
  );
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(missingAccessAuthority), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_DECOMMISSION_AUTHORITIES_INCOMPLETE'),
  );

  const missingDataAuthority = clone(decommissioned);
  Object.assign(
    missingDataAuthority.authorizations.find(({ id }) => id === 'AUTH-E9-DATA'),
    {
      status: 'PENDING',
      authorityRef: 'NOT_APPLICABLE',
      approvedAtUtc: 'NOT_APPLICABLE',
    },
  );
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(missingDataAuthority), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_DECOMMISSION_AUTHORITIES_INCOMPLETE'),
  );

  const routeConfusion = clone(decommissioned);
  routeConfusion.route = 'RETAINED';
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(routeConfusion), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_DECOMMISSION_ROUTE_INVALID'),
  );

  const residual = clone(decommissioned);
  residual.decommission.residualResourceCount = 1;
  assert.throws(
    () =>
      parseStage9PlanSource(asSource(residual), {
        intakeRawSha256: parsedIntake.rawSha256,
      }),
    stage9Error('E9_PLAN_DECOMMISSION_INCOMPLETE'),
  );

  return Object.freeze({
    status: 'PASS',
    assertions: 128,
    negativeCanaries: 32,
    artifacts: STAGE9_ARTIFACTS.length,
    evidence: STAGE9_EVIDENCE.length,
    auditControls: STAGE9_AUDIT_CONTROLS.length,
    authorizations: STAGE9_AUTHORIZATIONS.length,
    gates: STAGE9_GATES.length,
    catalogSha256: stage9CatalogSha256(),
    externalRequests: 0,
    awsCalls: 0,
    destructiveMutations: 0,
  });
};
