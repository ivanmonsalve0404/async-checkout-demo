import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { normalizePnpmScriptArguments } from './cli-arguments.mjs';

const workspaceRoot = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const entrypointBoundaries = Object.freeze({
  'scripts/stage7/aws-ops.mjs': 1,
  'scripts/stage7/baseline-cli.mjs': 0,
  'scripts/stage7/config-authoring.mjs': 1,
  'scripts/stage7/control.mjs': 1,
  'scripts/stage7/github-environment-approval.mjs': 0,
  'scripts/stage7/github-publication.mjs': 0,
  'scripts/stage7/prerelease-safety-readiness.mjs': 0,
  'scripts/stage7/runtime-secrets.mjs': 0,
  'scripts/stage7/sandbox-execution-claim.mjs': 0,
});

const expectContractFailure = (arguments_, options) => {
  assert.throws(
    () => normalizePnpmScriptArguments(arguments_, options),
    (error) => error?.code === 'E7_CLI_ARGUMENT_NORMALIZATION_CONTRACT_INVALID',
  );
};

const original = Object.freeze(['--', '--scope', 'prerelease']);
assert.deepEqual(normalizePnpmScriptArguments(original, { separatorIndex: 0 }), [
  '--scope',
  'prerelease',
]);
assert.deepEqual(original, ['--', '--scope', 'prerelease']);
assert.deepEqual(
  normalizePnpmScriptArguments(['synth', '--', '--scope', 'prerelease'], {
    separatorIndex: 1,
  }),
  ['synth', '--scope', 'prerelease'],
);
assert.deepEqual(normalizePnpmScriptArguments(['--scope', 'prerelease'], { separatorIndex: 0 }), [
  '--scope',
  'prerelease',
]);
assert.deepEqual(normalizePnpmScriptArguments(['--'], { separatorIndex: 0 }), ['--']);
assert.deepEqual(normalizePnpmScriptArguments(['synth', '--'], { separatorIndex: 1 }), [
  'synth',
  '--',
]);
assert.deepEqual(
  normalizePnpmScriptArguments(['--', '--', '--scope', 'prerelease'], { separatorIndex: 0 }),
  ['--', '--scope', 'prerelease'],
);
assert.deepEqual(
  normalizePnpmScriptArguments(['synth', '--', '--scope', 'prerelease', '--'], {
    separatorIndex: 1,
  }),
  ['synth', '--scope', 'prerelease', '--'],
);
assert.deepEqual(
  normalizePnpmScriptArguments(['--scope', '--', 'prerelease'], { separatorIndex: 0 }),
  ['--scope', '--', 'prerelease'],
);
expectContractFailure('not-an-array', { separatorIndex: 0 });
expectContractFailure([1], { separatorIndex: 0 });
expectContractFailure([], { separatorIndex: 2 });

for (const [relativePath, separatorIndex] of Object.entries(entrypointBoundaries)) {
  const source = readFileSync(path.join(workspaceRoot, relativePath), 'utf8');
  assert.match(source, /\bnormalizePnpmScriptArguments\(/u, `${relativePath} must normalize argv`);
  assert.match(
    source,
    new RegExp(`separatorIndex: ${separatorIndex}`, 'u'),
    `${relativePath} must use separator boundary ${separatorIndex}`,
  );
}

const arguments_ = normalizePnpmScriptArguments(process.argv.slice(2), { separatorIndex: 0 });
if (arguments_.length !== 0 && arguments_.join('\0') !== '--probe') {
  throw new Error('E7_CLI_ARGUMENT_SELF_TEST_SET_INVALID');
}
process.stdout.write(
  'stage-7 pnpm CLI argument contract self-test: PASS (9 entrypoints; 0 external calls)\n',
);
