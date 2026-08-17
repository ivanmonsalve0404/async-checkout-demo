import { strict as assert } from 'node:assert';
import process from 'node:process';

export const codeqlEvidenceStatus = ({
  ci,
  result,
  sha,
  candidateSha,
  sarifStatus,
  high,
  critical,
  sarifSha256,
}) => {
  if (!ci) return 'NOT_RUN_CI_REQUIRED';
  return result === 'success' &&
    sha === candidateSha &&
    sarifStatus === 'PASS' &&
    Number(high) === 0 &&
    Number(critical) === 0 &&
    /^[0-9a-f]{64}$/u.test(sarifSha256 ?? '')
    ? 'PASS'
    : 'FAIL';
};

if (process.argv.includes('--self-test')) {
  const candidateSha = 'a'.repeat(40);
  const cleanSarif = {
    ci: true,
    result: 'success',
    sha: candidateSha,
    candidateSha,
    sarifStatus: 'PASS',
    high: '0',
    critical: '0',
    sarifSha256: 'c'.repeat(64),
  };
  assert.equal(codeqlEvidenceStatus({ ci: false, candidateSha }), 'NOT_RUN_CI_REQUIRED');
  assert.equal(codeqlEvidenceStatus(cleanSarif), 'PASS');
  assert.equal(codeqlEvidenceStatus({ ...cleanSarif, sha: 'b'.repeat(40) }), 'FAIL');
  assert.equal(codeqlEvidenceStatus({ ...cleanSarif, result: 'failure' }), 'FAIL');
  assert.equal(codeqlEvidenceStatus({ ...cleanSarif, high: '1' }), 'FAIL');
  assert.equal(codeqlEvidenceStatus({ ...cleanSarif, critical: '1' }), 'FAIL');
  assert.equal(codeqlEvidenceStatus({ ...cleanSarif, sarifStatus: 'FAIL' }), 'FAIL');
  assert.equal(codeqlEvidenceStatus({ ...cleanSarif, sarifSha256: undefined }), 'FAIL');
  process.stdout.write('stage-6 CodeQL evidence self-test: PASS\n');
}
