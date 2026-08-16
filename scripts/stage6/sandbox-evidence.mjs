#!/usr/bin/env node
import process from 'node:process';

import {
  externalEvidenceCapabilityDecision,
  resolveExternalEvidence,
  selfTestExternalEvidence,
} from './external-evidence.mjs';
import { baseEvidence, candidate, stage6RunId, writeRuntimeEvidence } from './lib/evidence.mjs';

const COMMAND = 'node scripts/stage6/sandbox-evidence.mjs';

selfTestExternalEvidence();
if (process.argv.includes('--self-test')) {
  process.stdout.write('stage-6 sandbox evidence self-test: PASS\n');
  process.exit(0);
}

const runId = stage6RunId();
const currentCandidate = candidate();
const execution = { commitSha: currentCandidate.commitSha, runId };
const externalEvidence = await resolveExternalEvidence(execution);
const decision = externalEvidenceCapabilityDecision(externalEvidence, 'sandboxSmoke', execution);
const status =
  decision === 'PASS' ? 'PASS' : decision === 'NOT_RUN_AUTH_REQUIRED' ? decision : 'FAIL';
const evidence = {
  ...baseEvidence({
    artifactId: 'ART-VER-07',
    command: COMMAND,
    tool: { node: process.version, protocol: 'stage6-external-evidence-v1' },
    runId,
  }),
  commitSha: currentCandidate.commitSha,
  status,
  externalEvidence,
  ...(status === 'PASS'
    ? {
        sandboxSmoke: externalEvidence.capabilities.sandboxSmoke,
        authorizationsInvoked: ['AUTH-E6-02'],
      }
    : {}),
  ...(status === 'FAIL' ? { failureCode: externalEvidence.failureCode } : {}),
  externalRequestsByIngestion: 0,
  providerRequestsExecutedByThisProcess: 0,
  containsSensitiveData: false,
  declaration:
    status === 'PASS'
      ? 'AUTHORIZED_EXTERNAL_SANITIZED_SANDBOX_SMOKE_EVIDENCE'
      : status === 'NOT_RUN_AUTH_REQUIRED'
        ? 'SANDBOX_NOT_CONTACTED_AUTH_E6_02_REQUIRED'
        : 'CONFIGURED_EXTERNAL_EVIDENCE_REJECTED',
};

writeRuntimeEvidence('sandbox.json', evidence);
process.stdout.write(`stage-6 sandbox evidence: ${status} (0 external requests by ingestion)\n`);
if (status === 'FAIL') process.exitCode = 1;
else if (status === 'NOT_RUN_AUTH_REQUIRED') process.exitCode = 2;
