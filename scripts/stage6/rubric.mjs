#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import process from 'node:process';

const range = (start, end) =>
  Array.from(
    { length: end - start + 1 },
    (_, index) => `EVD-E6-${String(start + index).padStart(2, '0')}`,
  );

export const RUBRIC_DEFINITIONS = Object.freeze(
  [
    { id: 'RUB-BASE-01', category: 'BASE', max: 5, evidenceIds: ['EVD-E6-03', 'EVD-E6-40'] },
    {
      id: 'RUB-BASE-02',
      category: 'BASE',
      max: 5,
      evidenceIds: ['EVD-E6-26', 'EVD-E6-29', 'EVD-E6-36'],
    },
    {
      id: 'RUB-BASE-03',
      category: 'BASE',
      max: 20,
      evidenceIds: [...range(13, 23), 'EVD-E6-36'],
    },
    {
      id: 'RUB-BASE-04',
      category: 'BASE',
      max: 20,
      evidenceIds: ['EVD-E6-05', 'EVD-E6-11', 'EVD-E6-12', 'EVD-E6-34', 'EVD-E6-36'],
    },
    { id: 'RUB-BASE-05', category: 'BASE', max: 30, evidenceIds: range(6, 10) },
    {
      id: 'RUB-BASE-06',
      category: 'BASE',
      max: 20,
      evidenceIds: ['EVD-E6-24', 'EVD-E6-40'],
      relatedUatIds: ['UAT-33'],
    },
    { id: 'RUB-BONUS-01', category: 'BONUS', max: 5, evidenceIds: range(31, 35) },
    {
      id: 'RUB-BONUS-02',
      category: 'BONUS',
      max: 5,
      evidenceIds: ['EVD-E6-25', 'EVD-E6-36'],
    },
    {
      id: 'RUB-BONUS-03',
      category: 'BONUS',
      max: 10,
      evidenceIds: ['EVD-E6-26', 'EVD-E6-28', 'EVD-E6-29'],
    },
    {
      id: 'RUB-BONUS-04',
      category: 'BONUS',
      max: 10,
      evidenceIds: ['EVD-E6-04', 'EVD-E6-38', 'EVD-E6-40'],
    },
    {
      id: 'RUB-BONUS-05',
      category: 'BONUS',
      max: 10,
      evidenceIds: ['EVD-E6-10', 'EVD-E6-11', 'EVD-E6-12'],
    },
    {
      id: 'RUB-BONUS-06',
      category: 'BONUS',
      max: 10,
      evidenceIds: ['EVD-E6-07', 'EVD-E6-10', 'EVD-E6-12'],
    },
  ].map((definition) =>
    Object.freeze({
      ...definition,
      evidenceIds: Object.freeze(definition.evidenceIds),
      relatedUatIds: Object.freeze(definition.relatedUatIds ?? []),
    }),
  ),
);

const expectedEvidenceIds = range(1, 40);

const rubricStatus = (statuses) => {
  if (statuses.every((status) => status === 'PASS')) return 'PASS';
  if (statuses.some((status) => status === 'FAIL')) return 'FAIL';
  if (
    statuses.some((status) => ['NOT_RUN_AUTH_REQUIRED', 'CONDITIONAL_GO'].includes(status)) &&
    statuses.every((status) => ['PASS', 'NOT_RUN_AUTH_REQUIRED', 'CONDITIONAL_GO'].includes(status))
  ) {
    return 'NOT_RUN_AUTH_REQUIRED';
  }
  return 'BLOCKED';
};

export const calculateStage6Rubric = (evidence) => {
  if (!Array.isArray(evidence) || evidence.length !== expectedEvidenceIds.length) {
    throw new Error('STAGE6_RUBRIC_EVIDENCE_INCOMPLETE');
  }
  const byId = new Map(evidence.map(({ id, status }) => [id, status]));
  if (
    byId.size !== expectedEvidenceIds.length ||
    !expectedEvidenceIds.every((id) => typeof byId.get(id) === 'string')
  ) {
    throw new Error('STAGE6_RUBRIC_EVIDENCE_INVALID');
  }

  const results = RUBRIC_DEFINITIONS.map((definition) => {
    const statuses = definition.evidenceIds.map((id) => byId.get(id));
    const status = rubricStatus(statuses);
    return {
      id: definition.id,
      category: definition.category,
      status,
      awarded: status === 'PASS' ? definition.max : 0,
      max: definition.max,
      evidenceIds: [...definition.evidenceIds],
      relatedUatIds: [...definition.relatedUatIds],
    };
  });
  const totalFor = (category, field) =>
    results
      .filter((result) => result.category === category)
      .reduce((total, result) => total + result[field], 0);
  const baseTotal = { awarded: totalFor('BASE', 'awarded'), max: totalFor('BASE', 'max') };
  const bonusTotal = { awarded: totalFor('BONUS', 'awarded'), max: totalFor('BONUS', 'max') };
  return {
    schemaVersion: 1,
    status: results.every(({ status }) => status === 'PASS') ? 'PASS' : 'PARTIAL',
    scoring: 'ALL_OR_ZERO_PER_ROW_DERIVED_FROM_EVIDENCE',
    baseTotal,
    bonusTotal,
    results,
  };
};

export const stage6RubricIsExact = (rubric, evidence) => {
  try {
    assert.deepEqual(rubric, calculateStage6Rubric(evidence));
    return true;
  } catch {
    return false;
  }
};

export const selfTestStage6Rubric = () => {
  const evidence = expectedEvidenceIds.map((id) => ({ id, status: 'PASS' }));
  const full = calculateStage6Rubric(evidence);
  assert.equal(full.results.length, 12);
  assert.deepEqual(full.baseTotal, { awarded: 100, max: 100 });
  assert.deepEqual(full.bonusTotal, { awarded: 50, max: 50 });
  assert.equal(stage6RubricIsExact(full, evidence), true);

  const authStates = new Map([
    ['EVD-E6-24', 'NOT_RUN_AUTH_REQUIRED'],
    ['EVD-E6-33', 'NOT_RUN_AUTH_REQUIRED'],
    ['EVD-E6-36', 'PARTIAL_NOT_RUN_REQUIRED'],
    ['EVD-E6-40', 'CONDITIONAL_GO'],
  ]);
  const auth = evidence.map((entry) => ({
    ...entry,
    status: authStates.get(entry.id) ?? entry.status,
  }));
  const authRubric = calculateStage6Rubric(auth);
  assert.equal(
    authRubric.results.find(({ id }) => id === 'RUB-BASE-06')?.status,
    'NOT_RUN_AUTH_REQUIRED',
  );
  assert.deepEqual(authRubric.results.find(({ id }) => id === 'RUB-BASE-06')?.relatedUatIds, [
    'UAT-33',
  ]);
  assert.deepEqual(authRubric.baseTotal, { awarded: 30, max: 100 });
  assert.equal(
    stage6RubricIsExact({ ...full, baseTotal: { awarded: 101, max: 100 } }, evidence),
    false,
  );
  assert.throws(() => calculateStage6Rubric(evidence.slice(1)), /EVIDENCE_INCOMPLETE/u);
  assert.throws(
    () => calculateStage6Rubric([...evidence.slice(0, -1), evidence[0]]),
    /EVIDENCE_INVALID/u,
  );
};

if (process.argv.includes('--self-test')) {
  selfTestStage6Rubric();
  process.stdout.write('stage-6 rubric self-test: PASS\n');
}
