import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseStrictJsonSource, validateJsonSchemaSubset } from '../stage6/strict-json.mjs';
import {
  STAGE9_ARTIFACTS,
  STAGE9_AUDIT_CONTROLS,
  STAGE9_AUTHORIZATIONS,
  STAGE9_EVIDENCE,
} from './catalog.mjs';
import { Stage9ContractError, sha256, validateStage8Intake, validateStage9Plan } from './core.mjs';

const directory = path.dirname(fileURLToPath(import.meta.url));
const loadSchema = (name) =>
  JSON.parse(readFileSync(path.join(directory, name), { encoding: 'utf8' }));

export const STAGE8_ACCEPTANCE_HANDOFF_SCHEMA = loadSchema('stage8-acceptance-handoff.schema.json');
export const STAGE9_CLOSURE_PLAN_SCHEMA = loadSchema('stage9-closure-plan.schema.json');
const STAGE8_PROVIDER_HANDOFF_SCHEMA = JSON.parse(
  readFileSync(path.join(directory, '..', 'stage8', 'stage8-acceptance-handoff.schema.json'), {
    encoding: 'utf8',
  }),
);

const schemaForSubsetValidator = (value) => {
  if (Array.isArray(value)) return value.map(schemaForSubsetValidator);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key, child]) => !(key === 'type' && Array.isArray(child)))
      .map(([key, child]) => [key, schemaForSubsetValidator(child)]),
  );
};

const STAGE8_SUBSET_SCHEMA = schemaForSubsetValidator(STAGE8_ACCEPTANCE_HANDOFF_SCHEMA);

const schemaFailure = (code) => {
  throw new Stage9ContractError(code);
};

export const parseStage8IntakeSource = (source) => {
  let parsed;
  try {
    parsed = parseStrictJsonSource(source, { scanForbiddenData: false });
  } catch (error) {
    throw new Stage9ContractError('E9_INTAKE_SOURCE_INVALID', { cause: error });
  }
  if (!validateJsonSchemaSubset(parsed, STAGE8_SUBSET_SCHEMA)) {
    schemaFailure('E9_INTAKE_SCHEMA_INVALID');
  }
  const validated = validateStage8Intake(parsed);
  return Object.freeze({
    value: parsed,
    validated,
    rawSha256: sha256(source),
  });
};

export const parseStage9PlanSource = (source, { intakeRawSha256 }) => {
  let parsed;
  try {
    parsed = parseStrictJsonSource(source, { scanForbiddenData: false });
  } catch (error) {
    throw new Stage9ContractError('E9_PLAN_SOURCE_INVALID', { cause: error });
  }
  if (!validateJsonSchemaSubset(parsed, STAGE9_CLOSURE_PLAN_SCHEMA)) {
    schemaFailure('E9_PLAN_SCHEMA_INVALID');
  }
  const validated = validateStage9Plan(parsed, { intakeRawSha256 });
  return Object.freeze({
    value: parsed,
    validated,
    rawSha256: sha256(source),
  });
};

export const selfTestStage9Schemas = () => {
  const intake = STAGE8_ACCEPTANCE_HANDOFF_SCHEMA;
  const plan = STAGE9_CLOSURE_PLAN_SCHEMA;
  assert.deepEqual(intake, STAGE8_PROVIDER_HANDOFF_SCHEMA);
  assert.equal(intake.properties.kind.const, 'STAGE8_HANDOFF_TO_STAGE9');
  assert.equal(intake.properties.status.const, 'READY_FOR_STAGE9');
  assert.equal(intake.properties.decision.const, 'ACCEPTED');
  assert.deepEqual(intake.properties.gates.required, ['GATE-E8-01', 'GATE-E8-02', 'GATE-E8-03']);
  assert.equal(intake.properties.package.properties.artifacts.const, 16);
  assert.equal(intake.properties.package.properties.evidence.const, 48);
  assert.equal(intake.properties.package.properties.cases.const, 32);
  assert.equal(intake.properties.package.properties.auditControls.const, 72);
  assert.equal(intake.properties.delivery.properties.repositoryPublic.const, true);
  assert.equal(intake.properties.delivery.properties.readmeFinal.const, true);
  assert.equal(intake.properties.acceptance.properties.defectsAccepted.const, true);
  assert.equal(intake.properties.acceptance.properties.risksAccepted.const, true);
  assert.equal(intake.properties.acceptance.properties.deviationsAccepted.const, true);
  assert.equal(intake.required.includes('finalization'), true);
  assert.equal(intake.properties.release.required.includes('documentationCommit'), true);
  assert.equal(intake.properties.package.required.includes('evidenceInventorySha256'), true);
  assert.equal(intake.properties.package.required.includes('artifactBindingsSha256'), true);
  assert.equal(intake.required.includes('handoffSha256'), true);
  assert.equal(plan.properties.kind.const, 'STAGE9_LOCAL_NON_OPERATIVE_PLAN');
  assert.equal(plan.properties.authorizations.minItems, STAGE9_AUTHORIZATIONS.length);
  assert.equal(plan.properties.authorizations.maxItems, STAGE9_AUTHORIZATIONS.length);
  assert.equal(plan.properties.artifacts.minItems, STAGE9_ARTIFACTS.length);
  assert.equal(plan.properties.artifacts.maxItems, STAGE9_ARTIFACTS.length);
  assert.equal(plan.properties.evidence.minItems, STAGE9_EVIDENCE.length);
  assert.equal(plan.properties.evidence.maxItems, STAGE9_EVIDENCE.length);
  assert.equal(plan.properties.controls.minItems, STAGE9_AUDIT_CONTROLS.length);
  assert.equal(plan.properties.controls.maxItems, STAGE9_AUDIT_CONTROLS.length);
  assert.equal(plan.properties.requestedState.enum.includes('INTERVIEW_HOLD'), true);
  assert.equal(plan.properties.requestedState.enum.includes('CLOSED_RETAINED'), true);
  assert.equal(plan.properties.requestedState.enum.includes('CLOSED_DECOMMISSIONED'), true);
  assert.equal(plan.properties.requestedState.enum.includes('NOT_STARTED'), true);
  assert.equal(plan.properties.route.enum.includes('NONE'), true);
  assert.equal(plan.required.includes('sandboxExecution'), true);
  assert.equal(plan.properties.containsSensitiveData.const, false);
  return Object.freeze({ status: 'PASS', assertions: 35, externalRequests: 0, mutations: 0 });
};
