import { strict as assert } from 'node:assert';
import { resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ROW_AUTHORITY_TOKENS = new Set([
  'STATUS_BY_SAME_SHA_MANIFEST',
  'COMPLETE_BY_SAME_SHA_MANIFEST',
  'CALCULATED_BY_SAME_SHA_MANIFEST',
]);
const PROVISIONAL_CONTENT = /PENDING_VERIFICATION|No ejecutado/iu;
const RUN_ID_LITERAL = /\be6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}\b/u;
const SHA_LITERAL = /\b[0-9a-f]{40}\b/iu;
const REPORT_SECTION_AUTHORITY = [
  ['Resumen ejecutivo', ['EVD-E6-01']],
  ['Estado de entrada y prerrequisitos', ['EVD-E6-02', 'EVD-E6-03']],
  ['Commit candidato y baseline', ['SHA']],
  ['Entornos, autorizaciones y datos de prueba', ['AUTH-']],
  ['Plan de verificación y trazabilidad', ['ART-VER-01', 'ART-VER-03']],
  ['Verificación estática', ['EVD-E6-04']],
  ['Unit tests y cobertura frontend', ['EVD-E6-06', 'EVD-E6-08']],
  ['Unit tests y cobertura backend', ['EVD-E6-07', 'EVD-E6-09']],
  ['Integración frontend/backend/data', ['EVD-E6-11', 'EVD-E6-12']],
  ['OpenAPI y contract testing', ['EVD-E6-05']],
  ['Fake provider y E2E', ['EVD-E6-13', 'EVD-E6-14']],
  ['Integración sandbox', ['EVD-E6-24', 'AUTH-E6-02']],
  [
    'Integridad, concurrencia e idempotencia',
    ['EVD-E6-15', 'EVD-E6-16', 'EVD-E6-17', 'EVD-E6-18', 'EVD-E6-19', 'EVD-E6-20'],
  ],
  ['Resiliencia y recovery', ['EVD-E6-21', 'EVD-E6-22', 'EVD-E6-23']],
  ['Cross-browser y responsive', ['EVD-E6-25', 'EVD-E6-26']],
  ['Accesibilidad', ['EVD-E6-27', 'EVD-E6-28']],
  ['Rendimiento y carga', ['EVD-E6-29', 'EVD-E6-30']],
  ['Seguridad y privacidad', ['EVD-E6-31', 'EVD-E6-32', 'EVD-E6-33', 'EVD-E6-34', 'EVD-E6-35']],
  ['Observabilidad', ['observability', 'EVD-E6-35']],
  ['UAT', ['EVD-E6-36', 'UAT-']],
  ['Defectos, regresiones y flakiness', ['EVD-E6-37', 'EVD-E6-38']],
  ['Evidencias e índice', ['ART-VER-16']],
  ['Scorecard de rúbrica', ['EVD-E6-39', 'RUB-']],
  ['Evaluación GATE-E6-01', ['GATE-E6-01']],
  ['Evaluación GATE-E6-02', ['GATE-E6-02']],
  ['Evaluación GATE-E6-03', ['GATE-E6-03']],
  ['Release candidate y handoff a etapa 7', ['EVD-E6-40', 'releasePolicy']],
];

export const finalAuthorityText = (text) =>
  typeof text === 'string' && text.length > 0 && !PROVISIONAL_CONTENT.test(text);

export const canonicalRowsAuthorized = ({
  text,
  pattern,
  expectedIds,
  expectedStatuses,
  statusColumnIndex,
  expectedAuthorityToken,
}) => {
  if (
    !finalAuthorityText(text) ||
    !Array.isArray(expectedIds) ||
    !Array.isArray(expectedStatuses) ||
    expectedStatuses.length !== expectedIds.length ||
    !Number.isSafeInteger(statusColumnIndex) ||
    statusColumnIndex < 0 ||
    !ROW_AUTHORITY_TOKENS.has(expectedAuthorityToken)
  )
    return false;
  const rows = text
    .split('\n')
    .map((line) => ({ line, match: line.match(pattern) }))
    .filter(({ match }) => match !== null);
  if (
    rows.length !== expectedIds.length ||
    !rows.every(({ match }, index) => match[1] === expectedIds[index])
  ) {
    return false;
  }
  return rows.every(({ line }, index) => {
    if (!line.includes('`' + expectedAuthorityToken + '`')) return false;
    const cells = line.split('|').slice(1, -1);
    const actualStatus = cells[statusColumnIndex]?.replaceAll('`', '').trim();
    if (typeof actualStatus !== 'string' || actualStatus.length === 0) return false;
    const expectedStatus = expectedStatuses?.[index];
    return expectedStatus === undefined || actualStatus === expectedStatus;
  });
};

export const reportAuthorityReady = (text, expectedHeadingCount = 27) => {
  if (
    !finalAuthorityText(text) ||
    expectedHeadingCount !== REPORT_SECTION_AUTHORITY.length ||
    !text.includes('STATUS_BY_SAME_SHA_MANIFEST') ||
    !text.includes('RUN_ID_BY_SAME_SHA_MANIFEST') ||
    !text.includes('SHA_BY_SAME_SHA_MANIFEST') ||
    RUN_ID_LITERAL.test(text) ||
    SHA_LITERAL.test(text)
  )
    return false;
  const headings = [...text.matchAll(/^## (\d+)\.\s+(.+?)\s*$/gmu)];
  if (
    headings.length !== expectedHeadingCount ||
    !headings.every(
      (heading, index) =>
        Number(heading[1]) === index + 1 && heading[2] === REPORT_SECTION_AUTHORITY[index][0],
    )
  ) {
    return false;
  }
  const sections = headings.map((heading, index) => {
    const contentStart = (heading.index ?? 0) + heading[0].length;
    const contentEnd = headings[index + 1]?.index ?? text.length;
    return text
      .slice(contentStart, contentEnd)
      .replace(/<!--[^]*?-->/gu, '')
      .trim();
  });
  if (new Set(sections).size !== REPORT_SECTION_AUTHORITY.length) return false;
  return sections.every((content, index) => {
    if (content.length < 24 || !content.includes('STATUS_BY_SAME_SHA_MANIFEST')) return false;
    const normalized = content.toLowerCase();
    return REPORT_SECTION_AUTHORITY[index][1].every((anchor) =>
      normalized.includes(anchor.toLowerCase()),
    );
  });
};

export const selfTestDocumentAuthority = () => {
  const ids = ['UAT-01', 'UAT-02'];
  const goodRows = [
    '| `UAT-01` | `PASS` | `STATUS_BY_SAME_SHA_MANIFEST` |',
    '| `UAT-02` | `NOT_RUN_AUTH_REQUIRED` | `STATUS_BY_SAME_SHA_MANIFEST` |',
  ].join('\n');
  const rowOptions = {
    text: goodRows,
    pattern: /^\|\s*`(UAT-\d{2})`\s*\|/u,
    expectedIds: ids,
    expectedStatuses: ['PASS', 'NOT_RUN_AUTH_REQUIRED'],
    expectedAuthorityToken: 'STATUS_BY_SAME_SHA_MANIFEST',
    statusColumnIndex: 1,
  };
  assert.equal(canonicalRowsAuthorized(rowOptions), true);
  assert.equal(canonicalRowsAuthorized({ ...rowOptions, expectedStatuses: undefined }), false);
  assert.equal(
    canonicalRowsAuthorized({
      ...rowOptions,
      text: goodRows.replace('| `UAT-01` | `PASS` |', '| `UAT-01` | `FAIL` | detalle `PASS` |'),
    }),
    false,
  );
  assert.equal(
    canonicalRowsAuthorized({ ...rowOptions, text: 'STATUS_BY_SAME_SHA_MANIFEST' }),
    false,
  );
  assert.equal(
    canonicalRowsAuthorized({ ...rowOptions, text: '| `UAT-01` |\n| `UAT-02` |' }),
    false,
  );
  assert.equal(
    canonicalRowsAuthorized({
      ...rowOptions,
      text: goodRows.replaceAll('STATUS_BY_SAME_SHA_MANIFEST', 'X_BY_SAME_SHA_MANIFEST'),
    }),
    false,
  );
  assert.equal(
    canonicalRowsAuthorized({
      ...rowOptions,
      text: goodRows.replaceAll('STATUS_BY_SAME_SHA_MANIFEST', ''),
    }),
    false,
  );
  assert.equal(
    canonicalRowsAuthorized({
      ...rowOptions,
      text: goodRows.replaceAll('STATUS_BY_SAME_SHA_MANIFEST', 'X_BY_SAME_SHA_MANIFEST'),
      expectedAuthorityToken: 'X_BY_SAME_SHA_MANIFEST',
    }),
    false,
  );
  assert.equal(
    canonicalRowsAuthorized({
      ...rowOptions,
      text: goodRows.replace('`PASS`', '`PENDING_VERIFICATION`'),
    }),
    false,
  );
  assert.equal(canonicalRowsAuthorized({ ...rowOptions, text: goodRows.split('\n')[0] }), false);

  const populatedSections = REPORT_SECTION_AUTHORITY.map(
    ([title, anchors], index) =>
      `## ${index + 1}. ${title}\n${anchors.join(' ')}: resultado verificable específico de la sección ${index + 1}, autorizado por STATUS_BY_SAME_SHA_MANIFEST.`,
  ).join('\n\n');
  const populatedReport =
    '`RUN_ID_BY_SAME_SHA_MANIFEST`\n`SHA_BY_SAME_SHA_MANIFEST`\n\n' + populatedSections;

  assert.equal(reportAuthorityReady(populatedReport), true);
  assert.equal(
    reportAuthorityReady(
      populatedReport.replace('RUN_ID_BY_SAME_SHA_MANIFEST', 'X_BY_SAME_SHA_MANIFEST'),
    ),
    false,
  );
  assert.equal(
    reportAuthorityReady(
      populatedReport.replaceAll('STATUS_BY_SAME_SHA_MANIFEST', 'X_BY_SAME_SHA_MANIFEST'),
    ),
    false,
  );
  assert.equal(reportAuthorityReady(populatedReport + '\ne6-20260816t120000z-deadbeef'), false);
  assert.equal(
    reportAuthorityReady(populatedReport + '\n0123456789abcdef0123456789abcdef01234567'),
    false,
  );
  assert.equal(
    reportAuthorityReady(
      'STATUS_BY_SAME_SHA_MANIFEST GATE-E6-01 GATE-E6-02 GATE-E6-03 releasePolicy',
    ),
    false,
  );
  assert.equal(
    reportAuthorityReady(
      REPORT_SECTION_AUTHORITY.map(([title], index) => `## ${index + 1}. ${title}`).join('\n'),
    ),
    false,
  );
  const repeatedFiller = REPORT_SECTION_AUTHORITY.map(
    ([title], index) =>
      `## ${index + 1}. ${title}\nFrase genérica repetida autorizada por STATUS_BY_SAME_SHA_MANIFEST sin evidencia seccional.`,
  ).join('\n\n');
  assert.equal(reportAuthorityReady(repeatedFiller), false);
  assert.equal(
    reportAuthorityReady(populatedReport.replace('releasePolicy', 'release-state')),
    false,
  );
  assert.equal(finalAuthorityText('Narrativa histórica PENDING_FREEZE y NOT_SCORED.'), true);
  assert.equal(finalAuthorityText('Estado PENDING_VERIFICATION.'), false);
  assert.equal(finalAuthorityText('No ejecutado por autorización.'), false);
};

const executedDirectly =
  process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (executedDirectly && process.argv.includes('--self-test')) {
  selfTestDocumentAuthority();
  process.stdout.write('stage-6 document authority self-test: PASS\n');
}
