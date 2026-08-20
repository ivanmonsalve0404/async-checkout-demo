#!/usr/bin/env node

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

export const BASELINE_WORKFLOW = 'baseline.yml';
const BASELINE_JOBS = ['build-freeze', 'plan', 'establish', 'ensure-disabled', 'closeout'];

const normalize = (source) => source.replace(/\r\n?/gu, '\n');
const count = (source, fragment) => source.split(fragment).length - 1;

const jobIds = (source) => {
  const lines = normalize(source).split('\n');
  const start = lines.indexOf('jobs:');
  if (start < 0) return [];
  const result = [];
  for (const line of lines.slice(start + 1)) {
    if (line.length > 0 && !line.startsWith(' ')) break;
    const match = /^ {2}([a-z0-9-]+):$/u.exec(line);
    if (match !== null) result.push(match[1]);
  }
  return result;
};

const job = (source, name) => {
  const lines = normalize(source).split('\n');
  const start = lines.indexOf(`  ${name}:`);
  if (start < 0) return '';
  const end = lines.findIndex((line, index) => index > start && /^ {2}[a-z0-9-]+:$/u.test(line));
  return lines.slice(start, end < 0 ? lines.length : end).join('\n');
};

const jobCondition = (block) => {
  const lines = block.split('\n');
  const index = lines.findIndex((line) => /^ {4}if:/u.test(line));
  if (index < 0) return '';
  const value = /^ {4}if:\s*(.+?)\s*$/u.exec(lines[index])?.[1] ?? '';
  if (!['>', '>-', '|', '|-'].includes(value)) return value;
  const continuation = [];
  for (const line of lines.slice(index + 1)) {
    if (!/^ {6}/u.test(line)) break;
    continuation.push(line.trim());
  }
  return continuation.join(' ');
};

const hasAttemptOneGuard = (condition) => {
  if (condition.includes('||')) return false;
  return (
    condition
      .replace(/^\$\{\{\s*/u, '')
      .replace(/\s*\}\}$/u, '')
      .trim()
      .split(/\s*&&\s*/u)
      .filter((clause) => clause === 'github.run_attempt == 1').length === 1
  );
};

const withoutAttemptOneGuard = (block) => {
  const scalar = '    if: ${{ github.run_attempt == 1 }}\n';
  if (block.includes(scalar)) return block.replace(scalar, '');
  if (block.includes('github.run_attempt == 1 &&')) {
    return block.replace('github.run_attempt == 1 &&', '');
  }
  return block.replace(' && github.run_attempt == 1', '');
};

const hasInOrder = (source, fragments) => {
  let cursor = 0;
  for (const fragment of fragments) {
    const index = source.indexOf(fragment, cursor);
    if (index < 0) return false;
    cursor = index + fragment.length;
  }
  return true;
};

const uploadIsProtected = (block, artifactName) => {
  const marker = `          name: ${artifactName}`;
  const markerIndex = block.indexOf(marker);
  if (markerIndex < 0) return false;
  const stepStart = block.lastIndexOf('      - name:', markerIndex);
  const nextStep = block.indexOf('\n      - name:', markerIndex);
  const upload = block.slice(stepStart, nextStep < 0 ? block.length : nextStep);
  const before = block.slice(0, stepStart);
  return (
    upload.includes('uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02') &&
    upload.includes('          include-hidden-files: true') &&
    upload.includes('          if-no-files-found: error') &&
    /pnpm release:scan -- --pre-upload[^\n]+$/mu.test(before)
  );
};

export const validateBaselineWorkflow = (name, input) => {
  const source = normalize(input);
  const errors = [];
  const fail = (message) => errors.push(`${name}: ${message}`);
  const build = job(source, 'build-freeze');
  const plan = job(source, 'plan');
  const establish = job(source, 'establish');
  const recovery = job(source, 'ensure-disabled');
  const closeout = job(source, 'closeout');

  if (jobIds(source).join('\0') !== BASELINE_JOBS.join('\0')) {
    fail(
      'jobs must be the exact closed-baseline build, plan, establish, recovery, and closeout chain',
    );
  }
  for (const id of BASELINE_JOBS) {
    if (!hasAttemptOneGuard(jobCondition(job(source, id)))) {
      fail(`${id} must reject native reruns before any work`);
    }
  }
  if (
    count(source, '  workflow_dispatch:') !== 1 ||
    /\b(?:pull_request|pull_request_target|push|schedule)\s*:/u.test(source)
  ) {
    fail('the only trigger must be workflow_dispatch');
  }
  if (!/^permissions:\n  contents: read$/mu.test(source)) {
    fail('top-level permissions must be exactly contents: read');
  }
  for (const inputName of [
    'candidate_sha',
    'release_id',
    'baseline_version',
    'config_sha256',
    'stage6_run_id',
    'stage6_manifest_sha256',
    'stage6_artifact_id',
    'stage6_artifact_digest',
    'confirm_closed_baseline',
  ]) {
    if (!source.includes(`      ${inputName}:`)) fail(`required input is missing: ${inputName}`);
  }
  const actionReferences = [...source.matchAll(/^\s*uses:\s*([^\s#]+)/gmu)].map(
    (match) => match[1],
  );
  if (actionReferences.some((reference) => !/@[0-9a-f]{40}$/u.test(reference))) {
    fail('every action must be pinned to one immutable 40-character commit');
  }
  if (
    /STAGE7_PREVIOUS_[A-Z0-9_]*_B64|\bgit\s+tag\b|\bgh\s+release\b|GATE-E7-03[^\n]*PASS|README\.md[^\n]*(?:>|cp|mv)|cloudformation\s+delete-stack/iu.test(
      source,
    )
  ) {
    fail(
      'public release, manual predecessor B64, destructive cleanup, and Gate PASS effects are forbidden',
    );
  }
  if (
    !build.includes("github.ref == 'refs/heads/master'") ||
    !build.includes("github.repository == 'ivanmonsalve0404/async-checkout-demo'") ||
    !build.includes('inputs.confirm_closed_baseline == true') ||
    !build.includes('node scripts/stage7/stage6-source-provenance.mjs capture') ||
    !build.includes('--artifact-id "${STAGE6_ARTIFACT_ID}"') ||
    !build.includes('--artifact-digest "${STAGE6_ARTIFACT_DIGEST}"') ||
    !build.includes(
      '--stage6-source-provenance .stage7/freeze/baseline-stage6-source-provenance.json',
    ) ||
    !build.includes('--stage6-source-run-id "${STAGE6_SOURCE_RUN_ID}"') ||
    !build.includes('--stage6-source-artifact-id "${STAGE6_ARTIFACT_ID}"') ||
    !build.includes('--stage6-source-artifact-digest "${STAGE6_ARTIFACT_DIGEST}"') ||
    !build.includes('test -z "${AWS_ACCESS_KEY_ID:-}"') ||
    (!build.includes('--lookups') && !build.includes('release:baseline -- synth'))
  ) {
    fail('build-freeze must bind Stage 6 GitHub provenance and remain credential-free');
  }
  if (!uploadIsProtected(build, 'stage7-baseline-freeze')) {
    fail('hidden freeze upload requires an exact pre-upload scan and include-hidden-files');
  }
  if (
    count(plan, '    environment: assessment-release-read') !== 1 ||
    count(plan, '\n    environment:') !== 1 ||
    !plan.includes('role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}') ||
    plan.includes('STAGE7_AWS_BASELINE_ROLE_ARN') ||
    !plan.includes('--scope baseline --aws-read') ||
    !plan.includes('--cloud-assembly output/release/build/iac')
  ) {
    fail('plan must use only assessment-release-read/readRole and the frozen assembly');
  }
  if (!uploadIsProtected(plan, 'stage7-baseline-plan')) {
    fail('hidden plan upload requires an exact pre-upload scan and include-hidden-files');
  }
  if (
    !establish.includes('environment: assessment-release-baseline') ||
    !establish.includes('CONFIRM_BASELINE: ${{ inputs.confirm_closed_baseline') ||
    !establish.includes('STAGE7_PROTECTED_ENVIRONMENT: assessment-release-baseline') ||
    !establish.includes('role-to-assume: ${{ vars.STAGE7_AWS_BASELINE_ROLE_ARN }}') ||
    !hasInOrder(establish, [
      'release:baseline -- deploy',
      'release:baseline -- seed',
      'release:baseline -- notification',
      'release:baseline -- activate',
      'release:baseline -- smoke',
      'release:baseline -- disable',
    ]) ||
    !establish.includes("if: ${{ always() && steps.deploy.outcome == 'success' }}") ||
    !establish.includes("steps.smoke.outcome == 'success' && steps.disable.outcome == 'success'")
  ) {
    fail('establish must be protected, seed while disabled, smoke restricted, and always disable');
  }
  if (
    ![
      'STAGE7_BASELINE_SIGNED_COOKIE_B64',
      'STAGE7_BASELINE_EXPIRED_SIGNED_COOKIE_B64',
      'printf \'%s\' "${VALID_COOKIE_B64}" > .stage7/access/valid-cookie.b64',
      'printf \'%s\' "${EXPIRED_COOKIE_B64}" > .stage7/access/expired-cookie.b64',
      'chmod 600 .stage7/access/valid-cookie.b64 .stage7/access/expired-cookie.b64',
      '--valid-cookie .stage7/access/valid-cookie.b64',
      '--expired-cookie .stage7/access/expired-cookie.b64',
      'rm -f .stage7/access/valid-cookie.b64 .stage7/access/expired-cookie.b64',
    ].every((fragment) => establish.includes(fragment)) ||
    /(?:VALID|EXPIRED)_COOKIE_B64[^\n]*\|\s*base64\s+--decode/iu.test(establish) ||
    /(?:echo|tee|set\s+-x)[^\n]*(?:VALID|EXPIRED)_COOKIE_B64/iu.test(establish)
  ) {
    fail('establish signed-cookie secrets must use one opaque base64 layer without disclosure');
  }
  if (!uploadIsProtected(establish, 'stage7-baseline-capture-chain')) {
    fail('hidden capture-chain upload requires an exact pre-upload scan and include-hidden-files');
  }
  if (
    !recovery.includes(
      "if: ${{ always() && github.run_attempt == 1 && needs.build-freeze.result == 'success' }}",
    ) ||
    !recovery.includes('environment: assessment-release-recovery') ||
    !recovery.includes('STAGE7_PROTECTED_ENVIRONMENT: assessment-release-recovery') ||
    !recovery.includes('role-to-assume: ${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}') ||
    !recovery.includes('release:baseline -- recover-disable') ||
    !recovery.includes('baseline-disable.json')
  ) {
    fail('independent always-run rollbackRole recovery is required');
  }
  if (!uploadIsProtected(recovery, 'stage7-baseline-recovery')) {
    fail('hidden recovery upload requires an exact pre-upload scan and include-hidden-files');
  }
  if (
    !closeout.includes('- ensure-disabled') ||
    !closeout.includes('needs.ensure-disabled.result }}" = success') ||
    !closeout.includes('--final-disable .stage7/recovery/baseline-disable.json') ||
    !closeout.includes('--recovery-artifact-id "${RECOVERY_ARTIFACT_ID}"') ||
    !closeout.includes('--recovery-artifact-digest "${RECOVERY_ARTIFACT_DIGEST}"') ||
    !hasInOrder(closeout, [
      'Download the independent final-disable checkpoint',
      'Finalize the immutable N-1 bundle after independent recovery',
      'Upload the immutable post-recovery previous-release bundle',
    ]) ||
    !closeout.includes('Publication remains DISABLED') ||
    !closeout.includes('RB-E7-06 and RB-E7-08 remain blocked')
  ) {
    fail('closeout must require recovery and report only the closed blocked handoff');
  }
  if (!uploadIsProtected(closeout, 'stage7-previous-release')) {
    fail(
      'hidden post-recovery previous-release upload requires an exact pre-upload scan and include-hidden-files',
    );
  }
  return errors;
};

export const selfTestBaselineWorkflow = (source) => {
  assert.deepEqual(validateBaselineWorkflow(BASELINE_WORKFLOW, source), []);
  const canaries = [
    ['include-hidden-files: true', 'include-hidden-files: false', 'hidden freeze upload'],
    [
      'node scripts/stage7/stage6-source-provenance.mjs capture',
      'echo skipped',
      'Stage 6 GitHub provenance',
    ],
    [
      '--stage6-source-run-id "${STAGE6_SOURCE_RUN_ID}"',
      '--stage6-source-run-id "999999999"',
      'Stage 6 GitHub provenance',
    ],
    [
      '--stage6-source-artifact-id "${STAGE6_ARTIFACT_ID}"',
      '--stage6-source-artifact-id "999999999"',
      'Stage 6 GitHub provenance',
    ],
    [
      '--stage6-source-artifact-digest "${STAGE6_ARTIFACT_DIGEST}"',
      `--stage6-source-artifact-digest "sha256:${'0'.repeat(64)}"`,
      'Stage 6 GitHub provenance',
    ],
    [
      '    environment: assessment-release-read',
      '    environment: assessment-release',
      'assessment-release-read/readRole',
    ],
    ['release:baseline -- seed', 'release:baseline -- ignored-seed', 'seed while disabled'],
    [
      'printf \'%s\' "${VALID_COOKIE_B64}" > .stage7/access/valid-cookie.b64',
      'printf \'%s\' "${VALID_COOKIE_B64}" | base64 --decode > .stage7/access/valid-cookie.b64',
      'one opaque base64 layer',
    ],
    [
      'environment: assessment-release-recovery',
      'environment: assessment-release-baseline',
      'rollbackRole recovery',
    ],
    [
      'release:baseline -- recover-disable',
      'release:baseline -- validate-config',
      'rollbackRole recovery',
    ],
    [
      "if: ${{ always() && steps.deploy.outcome == 'success' }}",
      'if: ${{ success() }}',
      'always disable',
    ],
    [
      '--final-disable .stage7/recovery/baseline-disable.json',
      '--final-disable .stage7/capture-input/baseline-disable.json',
      'closeout must require recovery',
    ],
  ];
  for (const [from, to, expected] of canaries) {
    assert.ok(source.includes(from), `baseline workflow self-test fixture missing: ${from}`);
    const errors = validateBaselineWorkflow(BASELINE_WORKFLOW, source.replace(from, to));
    assert.ok(
      errors.some((error) => error.includes(expected)),
      `${expected}: ${errors.join('; ')}`,
    );
  }
  for (const id of BASELINE_JOBS) {
    const block = job(source, id);
    const mutated = source.replace(block, withoutAttemptOneGuard(block));
    const errors = validateBaselineWorkflow(BASELINE_WORKFLOW, mutated);
    assert.ok(
      errors.some((error) => error.includes(`${id} must reject native reruns before any work`)),
      `${id} native rerun guard: ${errors.join('; ')}`,
    );
  }
  const bypass = source.replace('github.run_attempt == 1 &&', 'github.run_attempt == 1 || true &&');
  assert.ok(
    validateBaselineWorkflow(BASELINE_WORKFLOW, bypass).some((error) =>
      error.includes('build-freeze must reject native reruns before any work'),
    ),
    'baseline native rerun guard must reject boolean bypasses',
  );
  return { status: 'PASS', assertions: canaries.length + BASELINE_JOBS.length + 2 };
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const filename = path.join(process.cwd(), '.github', 'workflows', BASELINE_WORKFLOW);
  const source = readFileSync(filename, 'utf8');
  if (process.argv[2] === '--self-test') {
    process.stdout.write(`${JSON.stringify(selfTestBaselineWorkflow(source))}\n`);
  } else {
    const errors = validateBaselineWorkflow(BASELINE_WORKFLOW, source);
    if (errors.length > 0) {
      for (const error of errors) process.stderr.write(`${error}\n`);
      process.exitCode = 1;
    } else {
      process.stdout.write('baseline-workflow-policy: PASS\n');
    }
  }
}
