#!/usr/bin/env node

import { existsSync, lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import {
  STAGE8_CATALOG,
  Stage8ContractError,
  canonicalJson,
  createStage8HandoffDraft,
  createStage8AssessmentTemplate,
  createStage8NotReady,
  deriveStage8State,
  finalizeStage8Acceptance,
  renderStage8Report,
  selfTestStage8Contract,
  validateStage7AcceptanceIntake,
  validateStage8Assessment,
  validateStage8TrustAnchor,
} from './contract.mjs';

const SOURCE_FILENAMES = {
  report: 'etapa-7-release-despliegue.md',
  manifest: 'release-manifest.json',
  ledger: 'provenance-ledger.json',
  closeout: 'closeout.json',
  handoff: 'handoff-payload.json',
};

const fail = (code) => {
  throw new Stage8ContractError(code);
};

const parseFlags = (values) => {
  const flags = {};
  for (let index = 0; index < values.length; index += 1) {
    const token = values[index];
    if (!/^--[a-z][a-z-]*$/u.test(token ?? '')) fail('E8_CLI_ARGUMENT_SET_INVALID');
    const name = token.slice(2);
    if (Object.hasOwn(flags, name)) fail('E8_CLI_ARGUMENT_DUPLICATE');
    const value = values[index + 1];
    if (value === undefined || value.startsWith('--')) fail('E8_CLI_ARGUMENT_VALUE_MISSING');
    flags[name] = value;
    index += 1;
  }
  return flags;
};

const exactFlagSet = (flags, names) =>
  Object.keys(flags).sort().join('\0') === [...names].sort().join('\0');

const exactObjectKeys = (value, names) =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join('\0') === [...names].sort().join('\0');

const readRegularFile = (filename, code) => {
  let status;
  try {
    status = lstatSync(filename);
  } catch {
    fail(`${code}_MISSING`);
  }
  if (!status.isFile() || status.isSymbolicLink()) fail(`${code}_NOT_REGULAR`);
  return readFileSync(filename);
};

const filesFromDirectory = (directory) => {
  const resolvedDirectory = path.resolve(directory);
  let realDirectory;
  try {
    const status = lstatSync(resolvedDirectory);
    if (!status.isDirectory() || status.isSymbolicLink()) fail('E8_CLI_INTAKE_DIRECTORY_INVALID');
    realDirectory = realpathSync(resolvedDirectory);
  } catch (error) {
    if (error instanceof Stage8ContractError) throw error;
    fail('E8_CLI_INTAKE_DIRECTORY_INVALID');
  }
  const prefix = realDirectory.endsWith(path.sep) ? realDirectory : `${realDirectory}${path.sep}`;
  return Object.fromEntries(
    Object.entries(SOURCE_FILENAMES).map(([name, basename]) => {
      const filename = path.join(realDirectory, basename);
      const source = readRegularFile(filename, `E8_CLI_${name.toUpperCase()}`);
      let realFilename;
      try {
        realFilename = realpathSync(filename);
      } catch {
        fail(`E8_CLI_${name.toUpperCase()}_MISSING`);
      }
      if (!realFilename.startsWith(prefix)) fail(`E8_CLI_${name.toUpperCase()}_PATH_ESCAPE`);
      return [name, source];
    }),
  );
};

const trustAnchorFromFile = (filename) => {
  const source = readRegularFile(path.resolve(filename), 'E8_CLI_TRUST_ANCHOR');
  let value;
  try {
    value = parseStrictJsonSource(source, { scanForbiddenData: false });
  } catch {
    fail('E8_CLI_TRUST_ANCHOR_JSON_INVALID');
  }
  return validateStage8TrustAnchor(value);
};

const assessmentFromFile = (filename, intake) => {
  const source = readRegularFile(path.resolve(filename), 'E8_CLI_ASSESSMENT');
  let value;
  try {
    value = parseStrictJsonSource(source, { scanForbiddenData: false });
  } catch {
    fail('E8_CLI_ASSESSMENT_JSON_INVALID');
  }
  return { source, value: validateStage8Assessment(value, intake) };
};

const jsonFromFile = (filename, code) => {
  const source = readRegularFile(path.resolve(filename), code);
  try {
    return parseStrictJsonSource(source, { scanForbiddenData: false });
  } catch {
    fail(`${code}_JSON_INVALID`);
  }
};

const authorizedAssessment = (flags, intake) => {
  const assessment = assessmentFromFile(flags.assessment, intake);
  return {
    assessment: assessment.value,
    assessmentSource: assessment.source,
    evidenceIndexSource: readRegularFile(
      path.resolve(flags['evidence-index']),
      'E8_CLI_EVIDENCE_INDEX',
    ),
    evidencePackageSource: readRegularFile(
      path.resolve(flags['evidence-package']),
      'E8_CLI_EVIDENCE_PACKAGE',
    ),
    evidenceAuthority: jsonFromFile(flags['evidence-authority'], 'E8_CLI_EVIDENCE_AUTHORITY'),
    evidenceRoot: path.resolve(flags['evidence-root']),
  };
};

const loadIntake = (flags) => {
  const files = filesFromDirectory(flags.directory);
  const trustAnchor = trustAnchorFromFile(flags['trust-anchor']);
  const authorityFilename = path.join(
    path.resolve(flags.directory),
    'documentation-commit-authority.json',
  );
  const authorityExpected = trustAnchor.documentationAuthorityRawSha256 !== null;
  if (!authorityExpected && existsSync(authorityFilename)) {
    fail('E8_CLI_DOCUMENTATION_AUTHORITY_UNEXPECTED');
  }
  const documentationAuthoritySource = authorityExpected
    ? readRegularFile(authorityFilename, 'E8_CLI_DOCUMENTATION_AUTHORITY')
    : undefined;
  return validateStage7AcceptanceIntake({
    files,
    trustAnchor,
    documentationAuthoritySource,
  });
};

const emitJson = (value) => process.stdout.write(`${canonicalJson(value)}\n`);

const HANDOFF_FLAGS = [
  'assessment',
  'directory',
  'evidence-authority',
  'evidence-index',
  'evidence-package',
  'evidence-root',
  'handoff-metadata',
  'report-source',
  'trust-anchor',
];

const handoffInput = (flags) => {
  const intake = loadIntake(flags);
  const material = authorizedAssessment(flags, intake);
  const snapshot = deriveStage8State({ intake, ...material });
  const metadata = jsonFromFile(flags['handoff-metadata'], 'E8_CLI_HANDOFF_METADATA');
  if (
    !exactObjectKeys(metadata, ['generatedAtUtc', 'report', 'delivery', 'acceptance', 'operation'])
  ) {
    fail('E8_CLI_HANDOFF_METADATA_INVALID');
  }
  return {
    snapshot,
    intake,
    ...material,
    ...metadata,
    reportSource: readRegularFile(path.resolve(flags['report-source']), 'E8_CLI_REPORT_SOURCE'),
  };
};

export const runStage8Cli = (arguments_) => {
  const [command, ...rest] = arguments_;
  if (command === 'self-test') {
    if (rest.length !== 0) fail('E8_CLI_ARGUMENT_SET_INVALID');
    const result = selfTestStage8Contract();
    process.stdout.write(
      `stage-8 acceptance contract self-test: PASS (${result.canaries} canaries; 0 network; 0 mutations; catalog sha256:${result.catalogSha256})\n`,
    );
    return;
  }
  if (command === 'catalog') {
    if (rest.length !== 0) fail('E8_CLI_ARGUMENT_SET_INVALID');
    emitJson(STAGE8_CATALOG);
    return;
  }
  if (command === 'blocked-report') {
    if (rest.length !== 0) fail('E8_CLI_ARGUMENT_SET_INVALID');
    process.stdout.write(renderStage8Report(createStage8NotReady()));
    return;
  }
  if (command === 'validate-intake') {
    const flags = parseFlags(rest);
    if (!exactFlagSet(flags, ['directory', 'trust-anchor'])) fail('E8_CLI_FLAG_SET_INVALID');
    emitJson(loadIntake(flags));
    return;
  }
  if (command === 'assessment-template') {
    const flags = parseFlags(rest);
    if (!exactFlagSet(flags, ['directory', 'trust-anchor'])) fail('E8_CLI_FLAG_SET_INVALID');
    emitJson(createStage8AssessmentTemplate(loadIntake(flags)));
    return;
  }
  if (command === 'state') {
    const flags = parseFlags(rest);
    if (exactFlagSet(flags, ['assessment', 'directory', 'trust-anchor'])) {
      loadIntake(flags);
      emitJson(createStage8NotReady('E8_EVIDENCE_AUTHORITY_MISSING'));
      return;
    }
    if (
      !exactFlagSet(flags, [
        'assessment',
        'directory',
        'evidence-authority',
        'evidence-index',
        'evidence-package',
        'evidence-root',
        'trust-anchor',
      ])
    ) {
      fail('E8_CLI_FLAG_SET_INVALID');
    }
    const intake = loadIntake(flags);
    emitJson(deriveStage8State({ intake, ...authorizedAssessment(flags, intake) }));
    return;
  }
  if (command === 'report') {
    const flags = parseFlags(rest);
    if (
      !exactFlagSet(flags, ['directory', 'trust-anchor']) &&
      !exactFlagSet(flags, ['assessment', 'directory', 'trust-anchor']) &&
      !exactFlagSet(flags, [
        'assessment',
        'directory',
        'evidence-authority',
        'evidence-index',
        'evidence-package',
        'evidence-root',
        'trust-anchor',
      ])
    ) {
      fail('E8_CLI_FLAG_SET_INVALID');
    }
    const intake = loadIntake(flags);
    if (exactFlagSet(flags, ['assessment', 'directory', 'trust-anchor'])) {
      process.stdout.write(
        renderStage8Report(createStage8NotReady('E8_EVIDENCE_AUTHORITY_MISSING')),
      );
      return;
    }
    const execution = flags.assessment === undefined ? {} : authorizedAssessment(flags, intake);
    process.stdout.write(renderStage8Report(deriveStage8State({ intake, ...execution })));
    return;
  }
  if (command === 'handoff-draft') {
    const flags = parseFlags(rest);
    if (!exactFlagSet(flags, HANDOFF_FLAGS)) fail('E8_CLI_FLAG_SET_INVALID');
    emitJson(createStage8HandoffDraft(handoffInput(flags)));
    return;
  }
  if (command === 'handoff') {
    const flags = parseFlags(rest);
    if (!exactFlagSet(flags, [...HANDOFF_FLAGS, 'finalization-authority'])) {
      fail('E8_CLI_FLAG_SET_INVALID');
    }
    const finalizationAuthoritySource = readRegularFile(
      path.resolve(flags['finalization-authority']),
      'E8_CLI_FINALIZATION_AUTHORITY',
    );
    emitJson(
      finalizeStage8Acceptance({
        ...handoffInput(flags),
        finalizationAuthoritySource,
      }).handoff,
    );
    return;
  }
  fail('E8_CLI_COMMAND_INVALID');
};

const executedDirectly =
  process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (executedDirectly) {
  try {
    runStage8Cli(process.argv.slice(2));
  } catch (error) {
    const code = error instanceof Stage8ContractError ? error.code : 'E8_CLI_UNEXPECTED_FAILURE';
    process.stderr.write(`stage-8 acceptance contract: FAIL (${code})\n`);
    process.exitCode = 1;
  }
}
