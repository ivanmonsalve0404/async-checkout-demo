import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  STAGE9_ARTIFACTS,
  STAGE9_AUDIT_CONTROLS,
  STAGE9_AUTHORIZATIONS,
  STAGE9_EVIDENCE,
  STAGE9_GATES,
  STAGE9_REPORT_SECTIONS,
} from './catalog.mjs';

const directory = path.dirname(fileURLToPath(import.meta.url));
const workspace = path.resolve(directory, '..', '..');
const readDocument = (name) =>
  readFileSync(path.join(workspace, 'docs', 'verification', name), { encoding: 'utf8' });

export const selfTestStage9Documents = () => {
  const contract = readDocument('stage9-local-contract.md');
  const template = readDocument('stage9-report-template.md');
  const sentinel = '<!-- STAGE9_LOCAL_PREPARATION_ONLY:NO_GATE_AUTHORITY -->';
  assert.equal(contract.split(sentinel).length - 1, 1);
  assert.equal(template.split(sentinel).length - 1, 1);
  assert.equal(contract.includes('BLK-E9-01'), true);
  assert.equal(contract.includes('READY_FOR_AUTHORIZED_PREFLIGHT'), true);
  assert.equal(contract.includes('no inicia una\nventana operativa'), true);
  assert.equal(contract.includes(`${STAGE9_ARTIFACTS.length} artefactos`), true);
  assert.equal(contract.includes(`${STAGE9_EVIDENCE.length} evidencias`), true);
  assert.equal(contract.includes(`${STAGE9_AUDIT_CONTROLS.length} controles`), true);
  assert.equal(
    contract.includes(`${STAGE9_AUTHORIZATIONS.length === 7 ? 'siete' : ''} autorizaciones`),
    true,
  );
  assert.equal(contract.includes(`${STAGE9_GATES.length === 3 ? 'tres' : ''} gates`), true);
  const headings = [...template.matchAll(/^## ([0-9]+)\. (.+)$/gmu)].map((match) => ({
    number: Number(match[1]),
    name: match[2],
  }));
  assert.equal(headings.length, STAGE9_REPORT_SECTIONS.length);
  assert.deepEqual(
    headings,
    STAGE9_REPORT_SECTIONS.map((name, index) => ({ number: index + 1, name })),
  );
  assert.equal(/GATE-E9-(?:01|02|03)\s*=\s*PASS/iu.test(template), false);
  assert.equal((template.match(/`NOT_EVALUATED`/gu) ?? []).length, 3);
  assert.equal(template.includes('BLK-E9-01_UNTIL_EXACT_ACCEPTED_HANDOFF'), true);
  return Object.freeze({ status: 'PASS', assertions: 15, externalRequests: 0, mutations: 0 });
};
