import { createHash } from 'node:crypto';
import path from 'node:path';

import { ROOT } from '../compat/harness.mjs';
import { writeSanitizedTextAtomic } from '../lib/artifact-sanitizer.mjs';

const relativePath = 'output/evidence/runtime/stage-6/performance-report.html';

const escapeHtml = (value) =>
  String(value ?? 'NOT_AVAILABLE')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

const metric = (source, name) => {
  const value = source?.metrics?.[name];
  if (value === undefined) return 'NOT_AVAILABLE';
  return `${value.median} ${value.unit} (range ${value.dispersion?.value ?? 'N/A'})`;
};

const row = (surface, visit, source) =>
  `<tr><th scope="row">${escapeHtml(surface)}</th><td>${escapeHtml(visit)}</td>` +
  `<td>${escapeHtml(source?.status)}</td><td>${escapeHtml(metric(source, 'lcpMs'))}</td>` +
  `<td>${escapeHtml(metric(source, 'cls'))}</td><td>${escapeHtml(metric(source, 'tbtMs'))}</td>` +
  `<td>${escapeHtml(metric(source, 'transferredBytes'))}</td>` +
  `<td>${escapeHtml(metric(source, 'performanceScore'))}</td>` +
  `<td>${escapeHtml(metric(source, 'accessibilityScore'))}</td>` +
  `<td>${escapeHtml(metric(source, 'bestPracticesScore'))}</td></tr>`;

export const writePerformanceHtml = async (report) => {
  const views = report.lighthouse?.views ?? {};
  const rows = [
    row('Product', 'first', views.product?.firstVisit),
    row('Product', 'repeat', views.product?.repeatVisit),
    row('Summary', 'user-flow', views.summary),
    row('Final', 'first', views.final?.firstVisit),
    row('Final', 'repeat', views.final?.repeatVisit),
  ].join('\n');
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
  <title>Stage 6 performance verification</title>
  <style>body{font:16px/1.5 system-ui,sans-serif;margin:2rem;color:#17202a}table{border-collapse:collapse;width:100%}caption{text-align:left;font-weight:700;margin-bottom:.5rem}th,td{border:1px solid #95a5a6;padding:.5rem;text-align:left}thead{background:#ecf0f1}code{overflow-wrap:anywhere}</style>
</head>
<body>
  <h1>Stage 6 performance verification</h1>
  <p>Status: <strong>${escapeHtml(report.status)}</strong></p>
  <p>Run: <code>${escapeHtml(report.runId)}</code>; commit: <code>${escapeHtml(report.commitSha)}</code></p>
  <p>Tool: ${escapeHtml(report.tool?.name)} ${escapeHtml(report.tool?.version)}. Scope: local synthetic loopback laboratory; no field-vitals claim.</p>
  <table>
    <caption>Sanitized Lighthouse medians and ranges</caption>
    <thead><tr><th scope="col">Surface</th><th scope="col">Visit</th><th scope="col">Status</th><th scope="col">LCP</th><th scope="col">CLS</th><th scope="col">TBT</th><th scope="col">Transfer</th><th scope="col">Performance</th><th scope="col">Accessibility</th><th scope="col">Best practices</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <h2>Budgets</h2>
  <ul><li>LCP &lt; ${escapeHtml(report.budgets?.lcpMsMaximumExclusive)} ms</li><li>CLS &lt; ${escapeHtml(report.budgets?.clsMaximumExclusive)}</li><li>Main image ≤ ${escapeHtml(report.budgets?.mainImageBytesMaximum)} bytes</li></ul>
  <p>Field LCP/CLS/INP: ${escapeHtml(report.fieldVitals?.lcpP75)} / ${escapeHtml(report.fieldVitals?.clsP75)} / ${escapeHtml(report.fieldVitals?.inpP75)}.</p>
  <p>Raw Lighthouse artifacts are intentionally not persisted; this report and its JSON peer contain only allowlisted aggregate values.</p>
</body>
</html>
`;
  const target = path.join(ROOT, ...relativePath.split('/'));
  const sanitizedHtml = await writeSanitizedTextAtomic(target, relativePath, html);
  return {
    path: relativePath,
    sha256: createHash('sha256').update(sanitizedHtml).digest('hex'),
    containsSensitiveData: false,
    rawArtifactsPersisted: false,
  };
};
