import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  Stage9ContractError,
  createStage9PlanTemplate,
  deriveStage9Entry,
  renderStage9CatalogMarkdown,
  renderStage9PreparationReport,
  stage9Catalog,
} from './core.mjs';
import { parseStage8IntakeSource, parseStage9PlanSource } from './schemas.mjs';
import { selfTestStage9 } from './self-test.mjs';

const directory = path.dirname(fileURLToPath(import.meta.url));
const workspace = path.resolve(directory, '..', '..');
const MAX_INPUT_BYTES = 1024 * 1024;

const fail = (code) => {
  throw new Stage9ContractError(code);
};

const parseFlags = (args) => {
  const flags = {};
  for (let index = 0; index < args.length; index += 1) {
    const key = args[index];
    if (!key.startsWith('--') || key === '--') fail('E9_CLI_FLAG_INVALID');
    const name = key.slice(2);
    if (name.length === 0 || Object.hasOwn(flags, name)) fail('E9_CLI_FLAG_INVALID');
    const value = args[index + 1];
    if (value === undefined || value.startsWith('--')) fail('E9_CLI_FLAG_VALUE_MISSING');
    flags[name] = value;
    index += 1;
  }
  return flags;
};

const exactFlags = (flags, expected) => {
  const actual = Object.keys(flags).toSorted();
  if (actual.join('\0') !== [...expected].toSorted().join('\0')) fail('E9_CLI_FLAGS_INVALID');
};

const readWorkspaceJson = (filename) => {
  if (typeof filename !== 'string' || !filename.toLowerCase().endsWith('.json')) {
    fail('E9_CLI_INPUT_PATH_INVALID');
  }
  const resolved = path.resolve(workspace, filename);
  const relative = path.relative(workspace, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative))
    fail('E9_CLI_INPUT_OUTSIDE_WORKSPACE');
  let stats;
  try {
    stats = lstatSync(resolved);
  } catch (error) {
    throw new Stage9ContractError('E9_CLI_INPUT_MISSING', { cause: error });
  }
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.size <= 0 ||
    stats.size > MAX_INPUT_BYTES
  ) {
    fail('E9_CLI_INPUT_FILE_INVALID');
  }
  const real = realpathSync(resolved);
  const realRelative = path.relative(workspace, real);
  if (realRelative.startsWith('..') || path.isAbsolute(realRelative)) {
    fail('E9_CLI_INPUT_OUTSIDE_WORKSPACE');
  }
  return readFileSync(real);
};

const writeJson = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);

const notReady = (reasonCode) => ({
  stage: 9,
  status: 'NOT_READY',
  decision: 'NOT_READY',
  blocker: 'BLK-E9-01',
  reasonCode,
  gates: {
    'GATE-E9-01': 'NOT_EVALUATED',
    'GATE-E9-02': 'NOT_EVALUATED',
    'GATE-E9-03': 'NOT_EVALUATED',
  },
  operationStarted: false,
  closureDeclared: false,
  externalRequests: 0,
  awsCalls: 0,
  destructiveMutations: 0,
  containsSensitiveData: false,
});

const validateIntakeCommand = (flags) => {
  exactFlags(flags, ['input']);
  try {
    const source = readWorkspaceJson(flags.input);
    const parsed = parseStage8IntakeSource(source);
    writeJson(deriveStage9Entry(parsed.value, { intakeRawSha256: parsed.rawSha256 }));
  } catch (error) {
    if (!(error instanceof Stage9ContractError)) throw error;
    writeJson(notReady(error.code));
    process.exitCode = 2;
  }
};

const validatePlanCommand = (flags) => {
  exactFlags(flags, ['intake', 'plan']);
  const intake = parseStage8IntakeSource(readWorkspaceJson(flags.intake));
  const plan = parseStage9PlanSource(readWorkspaceJson(flags.plan), {
    intakeRawSha256: intake.rawSha256,
  });
  writeJson({
    ...plan.validated,
    planRawSha256: plan.rawSha256,
    intakeRawSha256: intake.rawSha256,
    externalRequests: 0,
    awsCalls: 0,
    destructiveMutations: 0,
  });
};

const renderTemplateCommand = (flags) => {
  if (Object.keys(flags).length === 0) {
    const entry = deriveStage9Entry(undefined, { intakeRawSha256: '0'.repeat(64) });
    process.stdout.write(`${renderStage9PreparationReport(entry)}\n`);
    return;
  }
  exactFlags(flags, ['intake']);
  const parsed = parseStage8IntakeSource(readWorkspaceJson(flags.intake));
  const entry = deriveStage9Entry(parsed.value, { intakeRawSha256: parsed.rawSha256 });
  process.stdout.write(`${renderStage9PreparationReport(entry)}\n`);
};

const planTemplateCommand = (flags) => {
  exactFlags(flags, ['intake', 'planned-at']);
  const parsed = parseStage8IntakeSource(readWorkspaceJson(flags.intake));
  writeJson(
    createStage9PlanTemplate({
      entryBindingSha256: parsed.rawSha256,
      plannedAtUtc: flags['planned-at'],
    }),
  );
};

export const runStage9Cli = (args) => {
  const [command, ...rest] = args;
  if (command === undefined) fail('E9_CLI_COMMAND_REQUIRED');
  const flags = parseFlags(rest);
  if (command === 'self-test') {
    exactFlags(flags, []);
    writeJson(selfTestStage9());
    return;
  }
  if (command === 'catalog') {
    exactFlags(flags, ['format']);
    if (flags.format === 'json') writeJson(stage9Catalog());
    else if (flags.format === 'markdown') process.stdout.write(renderStage9CatalogMarkdown());
    else fail('E9_CLI_FORMAT_INVALID');
    return;
  }
  if (command === 'validate-intake') {
    validateIntakeCommand(flags);
    return;
  }
  if (command === 'validate-plan') {
    validatePlanCommand(flags);
    return;
  }
  if (command === 'render-template') {
    renderTemplateCommand(flags);
    return;
  }
  if (command === 'plan-template') {
    planTemplateCommand(flags);
    return;
  }
  fail('E9_CLI_COMMAND_INVALID');
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    runStage9Cli(process.argv.slice(2));
  } catch (error) {
    const code = error instanceof Stage9ContractError ? error.code : 'E9_CLI_UNEXPECTED_FAILURE';
    process.stderr.write(`stage-9 local contract: ${code}\n`);
    process.exitCode = 1;
  }
}
