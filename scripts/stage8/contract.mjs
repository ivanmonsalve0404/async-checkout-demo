import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import {
  STAGE7_ARTIFACTS as STAGE7_SOURCE_ARTIFACTS,
  STAGE7_EVIDENCE as STAGE7_SOURCE_EVIDENCE,
  createStage7Index,
  validateStage7Index,
} from '../stage7/core.mjs';
import {
  STAGE7_LEDGER_SOURCE_BINDING_SPECS,
  validateProvenanceRow as validateStage7ProvenanceRow,
  validateSourceReference as validateStage7SourceReference,
} from '../stage7/evidence-provenance.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const RELEASE_TAG =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$/u;
const ACCEPTANCE_ID = /^acc-[a-z0-9][a-z0-9._-]{7,95}$/u;
const ALIAS = /^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
const REPORT_FILENAME = 'etapa-8-aceptacion-evaluacion-final.md';
const MAX_EVIDENCE_FILE_BYTES = 1024 * 1024;
const MAX_EVIDENCE_TOTAL_BYTES = 16 * 1024 * 1024;

const URL_KEYS = ['application', 'api', 'docs', 'health', 'repository'];
const E7_GATES = ['GATE-E7-01', 'GATE-E7-02', 'GATE-E7-03'];
const E8_GATES = ['GATE-E8-01', 'GATE-E8-02', 'GATE-E8-03'];

const canonicalize = (value) => {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort((left, right) => left.localeCompare(right, 'en'))
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
};

export const canonicalJson = (value) => JSON.stringify(canonicalize(value));
export const rawSha256 = (source) =>
  createHash('sha256')
    .update(typeof source === 'string' ? Buffer.from(source) : source)
    .digest('hex');
export const objectSha256 = (value) => rawSha256(canonicalJson(value));

const deepFreeze = (value) => {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
};

const rows = (prefix, names, extras = []) =>
  names.map((name, index) => ({
    id: `${prefix}-${String(index + 1).padStart(2, '0')}`,
    name,
    ...(extras[index] ?? {}),
  }));

export const STAGE8_ARTIFACTS = deepFreeze(
  rows(
    'ART-ACC',
    [
      'Carta y baseline de aceptación',
      'Manifiesto de entrega pública',
      'Reporte de acceso independiente',
      'Auditoría de repositorio y README',
      'Reporte funcional',
      'Reporte API y datos',
      'Reporte de calidad',
      'Reporte de seguridad y privacidad',
      'Revisión de código y arquitectura',
      'Scorecard de rúbrica',
      'Registro de defectos y desviaciones',
      'Plan y guion de demo',
      'Paquete de demo',
      'Decisión de aceptación',
      'Handoff a etapa 9',
      'Índice final de evidencia',
    ],
    [
      { contentMinimum: 'Alcance, roles, release e inputs', acceptedState: 'VERIFIED' },
      { contentMinimum: 'URLs, SHA, tag y checksums', acceptedState: 'VERIFIED' },
      { contentMinimum: 'Incógnito, enlaces y disponibilidad', acceptedState: 'VERIFIED' },
      {
        contentMinimum: 'Visibilidad, historia, contenido y limpieza',
        acceptedState: 'VERIFIED',
      },
      { contentMinimum: 'Casos críticos y resultados', acceptedState: 'VERIFIED' },
      {
        contentMinimum: 'Recursos, HTTP, contratos e invariantes',
        acceptedState: 'VERIFIED',
      },
      {
        contentMinimum: 'Cobertura, browsers, a11y, rendimiento',
        acceptedState: 'VERIFIED',
      },
      {
        contentMinimum: 'Sandbox, secretos, headers y datos',
        acceptedState: 'VERIFIED',
      },
      { contentMinimum: 'Clean code, hexagonal, ROP', acceptedState: 'VERIFIED' },
      { contentMinimum: 'Base, bonus, riesgo y evidencia', acceptedState: 'VERIFIED' },
      {
        contentMinimum: 'Severidad, owner y retorno',
        acceptedState: 'CLOSED_OR_ACCEPTED',
      },
      { contentMinimum: 'Recorrido, tiempos y contingencias', acceptedState: 'REHEARSED' },
      { contentMinimum: 'Datos sintéticos, bookmarks y evidencia', acceptedState: 'READY' },
      { contentMinimum: 'Dictamen, firmas y condiciones', acceptedState: 'ACCEPTED' },
      { contentMinimum: 'Operación, expiración y pendientes', acceptedState: 'READY' },
      {
        contentMinimum: 'Rutas, hashes, timestamps y owners',
        acceptedState: 'VERIFIED',
      },
    ],
  ),
);

export const STAGE8_EVIDENCE = deepFreeze(
  rows(
    'EVD-E8',
    [
      'Handoff de etapa 7',
      'GATES E7-01/02/03',
      'Release ID, SHA, tag y hashes',
      'URLs abiertas en incógnito',
      'Repositorio visible sin login',
      'Nombre/metadata del repo',
      'Historial progresivo de commits',
      'Secret scan de árbol, historial y artifacts',
      'README renderizado',
      'Enlaces de app, API y docs desde README',
      'Inicio en sesión limpia',
      'Producto, precio y stock',
      'Modal de tarjeta y entrega',
      'Validaciones de formulario',
      'Resumen con tres componentes de precio',
      'Transacción local PENDING',
      'Caso aprobado sandbox',
      'Un decremento y una entrega',
      'Caso rechazado/error',
      'Resultado desconocido/reconciliación',
      'Resultado final y retorno a producto',
      'Recuperación tras refresh',
      'Replay/doble clic',
      'Última unidad/concurrencia',
      'API de stock',
      'API de transacciones',
      'API de clientes',
      'API de entregas',
      'Validaciones y códigos HTTP',
      'Swagger/OpenAPI público y sanitizado',
      'Jest frontend >80 %',
      'Jest backend >80 %',
      'Reejecución reproducible de cobertura',
      'Responsive en viewports aprobados',
      'Chromium/Firefox/WebKit',
      'Accesibilidad automatizada y manual',
      'Imágenes, overflow y rendimiento',
      'HTTPS, headers y Observatory/DAST',
      'Ausencia de PAN/CVC/secrets/PII indebida',
      'SPA y API cloud operativas',
      'Logs, métricas, alarmas y rollback',
      'Revisión clean code',
      'Evidencia hexagonal/Ports & Adapters',
      'Evidencia ROP',
      'Scorecard base y bonus',
      'Registro de defectos/desviaciones',
      'Rehearsal de demo',
      'Dictamen y handoff a etapa 9',
    ],
    [
      { associationMinimum: 'Gate E8-01' },
      { associationMinimum: 'Gate E8-01' },
      { associationMinimum: 'Integridad' },
      { associationMinimum: 'Acceso público' },
      { associationMinimum: 'Entregable' },
      { associationMinimum: 'Restricción de marca' },
      { associationMinimum: 'Originalidad' },
      { associationMinimum: 'Seguridad' },
      { associationMinimum: 'RUB-01' },
      { associationMinimum: 'RUB-01/06' },
      { associationMinimum: 'Flujo' },
      { associationMinimum: 'RUB-03' },
      { associationMinimum: 'RUB-03' },
      { associationMinimum: 'RUB-03' },
      { associationMinimum: 'RUB-03' },
      { associationMinimum: 'RUB-03/04' },
      { associationMinimum: 'RUB-03' },
      { associationMinimum: 'Regla de negocio' },
      { associationMinimum: 'Regla de negocio' },
      { associationMinimum: 'Resiliencia' },
      { associationMinimum: 'Flujo' },
      { associationMinimum: 'Resiliencia' },
      { associationMinimum: 'Idempotencia' },
      { associationMinimum: 'Stock' },
      { associationMinimum: 'RUB-04' },
      { associationMinimum: 'RUB-04' },
      { associationMinimum: 'RUB-04' },
      { associationMinimum: 'RUB-04' },
      { associationMinimum: 'RUB-04' },
      { associationMinimum: 'RUB-04' },
      { associationMinimum: 'RUB-05' },
      { associationMinimum: 'RUB-05' },
      { associationMinimum: 'RUB-05' },
      { associationMinimum: 'RUB-02/08/09' },
      { associationMinimum: 'RUB-08' },
      { associationMinimum: 'Calidad' },
      { associationMinimum: 'RUB-02/09' },
      { associationMinimum: 'RUB-07' },
      { associationMinimum: 'Seguridad' },
      { associationMinimum: 'RUB-06' },
      { associationMinimum: 'Operabilidad' },
      { associationMinimum: 'RUB-10' },
      { associationMinimum: 'RUB-11' },
      { associationMinimum: 'RUB-12' },
      { associationMinimum: 'Evaluación' },
      { associationMinimum: 'Decisión' },
      { associationMinimum: 'Presentación' },
      { associationMinimum: 'Cierre' },
    ],
  ),
);

const evidenceIds = (...numbers) =>
  numbers.map((number) => `EVD-E8-${String(number).padStart(2, '0')}`);

export const STAGE8_ARTIFACT_EVIDENCE_BINDINGS = deepFreeze([
  { id: 'ART-ACC-01', material: 'EVIDENCE_SET', evidenceIds: evidenceIds(1, 2, 3) },
  { id: 'ART-ACC-02', material: 'EVIDENCE_SET', evidenceIds: evidenceIds(3, 4, 5, 10, 39) },
  { id: 'ART-ACC-03', material: 'EVIDENCE_SET', evidenceIds: evidenceIds(4, 5, 10, 11) },
  { id: 'ART-ACC-04', material: 'EVIDENCE_SET', evidenceIds: evidenceIds(5, 6, 7, 8, 9, 10) },
  {
    id: 'ART-ACC-05',
    material: 'EVIDENCE_SET',
    evidenceIds: evidenceIds(...Array.from({ length: 14 }, (_, index) => index + 11)),
  },
  {
    id: 'ART-ACC-06',
    material: 'EVIDENCE_SET',
    evidenceIds: evidenceIds(...Array.from({ length: 6 }, (_, index) => index + 25)),
  },
  {
    id: 'ART-ACC-07',
    material: 'EVIDENCE_SET',
    evidenceIds: evidenceIds(...Array.from({ length: 7 }, (_, index) => index + 31)),
  },
  { id: 'ART-ACC-08', material: 'EVIDENCE_SET', evidenceIds: evidenceIds(8, 38, 39, 40) },
  { id: 'ART-ACC-09', material: 'EVIDENCE_SET', evidenceIds: evidenceIds(41, 42, 43) },
  { id: 'ART-ACC-10', material: 'EVIDENCE_SET', evidenceIds: evidenceIds(44) },
  { id: 'ART-ACC-11', material: 'EVIDENCE_SET', evidenceIds: evidenceIds(45) },
  { id: 'ART-ACC-12', material: 'EVIDENCE_SET', evidenceIds: evidenceIds(46) },
  { id: 'ART-ACC-13', material: 'EVIDENCE_SET', evidenceIds: evidenceIds(11, 17, 46) },
  { id: 'ART-ACC-14', material: 'ASSESSMENT', evidenceIds: evidenceIds(47) },
  { id: 'ART-ACC-15', material: 'HANDOFF', evidenceIds: evidenceIds(48) },
  {
    id: 'ART-ACC-16',
    material: 'EVIDENCE_INDEX',
    evidenceIds: evidenceIds(...Array.from({ length: 48 }, (_, index) => index + 1)),
  },
]);
export const STAGE8_ARTIFACT_BINDINGS_SHA256 = objectSha256(STAGE8_ARTIFACT_EVIDENCE_BINDINGS);

export const STAGE8_CASES = deepFreeze(
  rows(
    'ACC-TC',
    [
      'Abrir SPA desde README en incógnito',
      'Abrir API y Swagger',
      'Abrir repo sin login',
      'Sesión nueva',
      'Stock agotado',
      'Abrir “pagar con tarjeta”',
      'Tarjeta inválida',
      'Entrega incompleta',
      'Refresh en captura',
      'Revisar totales',
      'Doble clic',
      'Iniciar pago',
      'Resultado aprobado',
      'Efectos aprobados',
      'Resultado rechazado',
      'Resultado error',
      'Resultado desconocido',
      'Resultado y retorno',
      'Dos compras por última unidad',
      'Dos pestañas/replay',
      'Stock',
      'Transacciones',
      'Clientes',
      'Entregas',
      'HTTP y errores',
      'Jest frontend',
      'Jest backend',
      'Viewports aprobados',
      'Chromium/Firefox/WebKit',
      'Teclado, foco y lector',
      'Carga e imágenes',
      'TLS, headers y datos',
    ],
    [
      { area: 'Acceso', expected: 'Carga por HTTPS' },
      { area: 'Acceso', expected: 'Públicos y sanitizados' },
      { area: 'Repositorio', expected: 'Visible y evaluable' },
      { area: 'Producto', expected: 'Producto, descripción, precio y stock' },
      { area: 'Producto', expected: 'Pago bloqueado con mensaje claro' },
      { area: 'Checkout', expected: 'Modal accesible' },
      { area: 'Validación', expected: 'Error específico, sin submit' },
      { area: 'Validación', expected: 'Error específico, sin submit' },
      { area: 'Resiliencia', expected: 'Progreso no sensible recuperado' },
      { area: 'Resumen', expected: 'Producto + base + entrega = total' },
      { area: 'Idempotencia', expected: 'Una intención/transacción efectiva' },
      { area: 'Pago', expected: 'Transacción local PENDING con ID' },
      { area: 'Pago', expected: 'Estado final consistente' },
      { area: 'Negocio', expected: 'Un decremento y una entrega' },
      { area: 'Pago', expected: 'Sin decremento ni entrega' },
      { area: 'Pago', expected: 'Sin decremento ni entrega' },
      { area: 'Pago', expected: 'Reserva y reconciliación, sin falsa conclusión' },
      { area: 'Flujo', expected: 'Estado visible y stock actualizado' },
      { area: 'Concurrencia', expected: 'Máximo una aprobada con consumo' },
      { area: 'Sesión', expected: 'Sin efectos duplicados' },
      { area: 'API', expected: 'Lecturas/actualizaciones permitidas correctas' },
      { area: 'API', expected: 'Creación/consulta/actualización controladas' },
      { area: 'API', expected: 'Validación y persistencia segura' },
      { area: 'API', expected: 'Una entrega sólo para aprobación' },
      { area: 'API', expected: 'Códigos y envelope coherentes' },
      { area: 'Calidad', expected: '>80 % reproducible' },
      { area: 'Calidad', expected: '>80 % reproducible' },
      { area: 'Responsive', expected: 'Sin overflow ni controles cortados' },
      { area: 'Browser', expected: 'Flujo crítico correcto' },
      { area: 'Accesibilidad', expected: 'Cero barreras P0/P1' },
      { area: 'Rendimiento', expected: 'Presupuestos aceptados' },
      { area: 'Seguridad', expected: 'Sin hallazgos críticos/altos abiertos' },
    ],
  ),
);

export const STAGE8_AUDIT_CONTROLS = deepFreeze(
  rows(
    'ACCAUD',
    [
      'Gate E7-03',
      'Release ID',
      'Runtime SHA',
      'Submission SHA',
      'Tag',
      'Checksums',
      'Carta aceptación',
      'Evaluador/roles',
      'Entorno limpio',
      'Autorizaciones',
      'SPA URL',
      'API URL',
      'Swagger URL',
      'Health URL',
      'Repo visibilidad',
      'Repo nombre/metadata',
      'Historial',
      'Originalidad',
      'Secret scan árbol',
      'Secret scan historial/logs',
      'README contenido',
      'README comandos',
      'README links',
      'README coverage',
      'Producto',
      'Precio/moneda',
      'Stock',
      'CTA/modal',
      'Tarjeta validación',
      'Entrega validación',
      'Datos sensibles cliente',
      'Refresh captura',
      'Resumen/fees',
      'Aceptaciones',
      'Local PENDING',
      'Approved estado',
      'Approved stock',
      'Approved delivery',
      'Declined',
      'Error',
      'Unknown/pending',
      'Resultado UI',
      'Retorno producto',
      'Doble clic/replay',
      'Última unidad',
      'Dos pestañas',
      'API stock',
      'API transactions',
      'API customers',
      'API deliveries',
      'HTTP/errores',
      'OpenAPI drift',
      'Jest frontend',
      'Jest backend',
      'Coverage reproducible',
      'Responsive',
      'Cross-browser',
      'Accesibilidad',
      'Imágenes/overflow',
      'Rendimiento',
      'HTTPS/headers',
      'CORS/cookies',
      'PAN/CVC/secrets',
      'Sandbox exclusivo',
      'Cloud app/API',
      'Clean code',
      'Hexagonal',
      'ROP',
      'Base score',
      'Bonus score',
      'Demo',
      'Handoff/decisión',
    ],
    [
      { criterion: 'PASS' },
      { criterion: 'Único' },
      { criterion: 'Coincide despliegue' },
      { criterion: 'Coincide repo' },
      { criterion: 'Inmutable' },
      { criterion: 'Verificados' },
      { criterion: 'Completa' },
      { criterion: 'Registrados' },
      { criterion: 'PASS' },
      { criterion: 'Vigentes' },
      { criterion: 'Pública/HTTPS' },
      { criterion: 'Pública/HTTPS' },
      { criterion: 'Pública/sanitizada' },
      { criterion: 'PASS' },
      { criterion: 'Público' },
      { criterion: 'Aprobados' },
      { criterion: 'Progreso visible' },
      { criterion: 'Sin señales no resueltas' },
      { criterion: '0 confirmados' },
      { criterion: '0 confirmados' },
      { criterion: 'Completo' },
      { criterion: 'Reproducibles' },
      { criterion: '100 % válidos' },
      { criterion: 'Coincide reportes' },
      { criterion: 'Visible/correcto' },
      { criterion: 'Correctos' },
      { criterion: 'Visible/no negativo' },
      { criterion: 'PASS' },
      { criterion: 'PASS' },
      { criterion: 'PASS' },
      { criterion: 'No persistidos' },
      { criterion: 'PASS' },
      { criterion: 'Exactos' },
      { criterion: 'Correctas' },
      { criterion: 'Antes de provider' },
      { criterion: 'Correcto' },
      { criterion: 'Un efecto' },
      { criterion: 'Una entrega' },
      { criterion: 'Sin stock/entrega' },
      { criterion: 'Sin stock/entrega' },
      { criterion: 'Reconciliable' },
      { criterion: 'Claro' },
      { criterion: 'Stock actualizado' },
      { criterion: 'Idempotente' },
      { criterion: 'Concurrencia segura' },
      { criterion: 'Sin duplicados' },
      { criterion: 'PASS' },
      { criterion: 'PASS' },
      { criterion: 'PASS' },
      { criterion: 'PASS' },
      { criterion: 'Coherentes' },
      { criterion: '0 crítico' },
      { criterion: '>80 %' },
      { criterion: '>80 %' },
      { criterion: 'PASS' },
      { criterion: 'PASS' },
      { criterion: 'PASS' },
      { criterion: '0 P0/P1' },
      { criterion: 'PASS' },
      { criterion: 'PASS/riesgo P2' },
      { criterion: 'PASS' },
      { criterion: 'PASS' },
      { criterion: '0' },
      { criterion: 'PASS' },
      { criterion: 'Integradas' },
      { criterion: 'Evaluado' },
      { criterion: 'Evaluada' },
      { criterion: 'Evaluado' },
      { criterion: '100/100' },
      { criterion: 'Evaluado' },
      { criterion: 'Rehearsed' },
      { criterion: 'Completo/ACCEPTED' },
    ],
  ),
);

export const STAGE8_GATE_DEFINITIONS = deepFreeze([
  {
    id: 'GATE-E8-01',
    name: 'Entrega y evidencia listas para evaluación',
    controls: [
      { control: 'GATE-E7-03', threshold: 'PASS' },
      { control: 'Release ID/SHA/tag', threshold: 'Coherentes' },
      { control: 'Checksums', threshold: '100 % verificados' },
      { control: 'URLs obligatorias', threshold: 'Presentes' },
      { control: 'Repositorio', threshold: 'Público' },
      { control: 'README', threshold: 'Renderiza y enlaza entrega' },
      { control: 'Evidencia etapa 7', threshold: 'Completa' },
      { control: 'P0/P1 heredados', threshold: '0 abiertos' },
      {
        control: 'Autorización sandbox',
        threshold: 'Vigente o caso marcado bloqueado antes de iniciar',
      },
      { control: 'Carta de aceptación', threshold: 'Completa' },
      { control: 'Entorno limpio', threshold: 'Preparado' },
      { control: 'Secret scan inicial', threshold: '0 confirmados' },
      { control: 'Identidad de evaluator', threshold: 'Registrada' },
    ],
    states: ['PASS', 'FAIL'],
  },
  {
    id: 'GATE-E8-02',
    name: 'Aceptación funcional y técnica independiente',
    controls: [
      { control: 'Casos de aceptación', threshold: '32/32' },
      { control: 'Flujo de cinco pasos', threshold: 'PASS' },
      { control: 'Aprobado', threshold: 'Efecto único' },
      { control: 'Rechazado/error', threshold: 'Sin stock ni entrega' },
      { control: 'Resultado desconocido', threshold: 'Reconciliable' },
      { control: 'Recuperación', threshold: 'PASS' },
      { control: 'Idempotencia/concurrencia', threshold: 'PASS' },
      { control: 'API recursos obligatorios', threshold: 'PASS' },
      { control: 'OpenAPI/runtime drift', threshold: '0 crítico' },
      { control: 'Jest frontend', threshold: '>80 %' },
      { control: 'Jest backend', threshold: '>80 %' },
      { control: 'Responsive/browser', threshold: 'PASS' },
      { control: 'Accesibilidad', threshold: '0 P0/P1' },
      {
        control: 'Rendimiento/imágenes',
        threshold: 'PASS o P2 aceptado sin afectar rubro',
      },
      { control: 'Seguridad crítica/alta', threshold: '0 no aceptadas' },
      { control: 'Producción/pago real', threshold: '0' },
      { control: 'Secretos/PAN/CVC', threshold: '0' },
      { control: 'Defectos P0/P1', threshold: '0' },
      { control: 'Disqualifiers', threshold: '0' },
    ],
    states: ['PASS', 'BLOCKED_EXTERNAL', 'FAIL'],
  },
  {
    id: 'GATE-E8-03',
    name: 'Evaluación final, demo y aceptación',
    controls: [
      { control: 'GATE-E8-01', threshold: 'PASS' },
      { control: 'GATE-E8-02', threshold: 'PASS' },
      { control: 'Artefactos', threshold: '16/16' },
      { control: 'Evidencias', threshold: '48/48 o N/A aprobado' },
      { control: 'Base score', threshold: '100/100 verificados' },
      { control: 'Bonus score', threshold: 'Evaluado con evidencia' },
      { control: 'Confianza base', threshold: 'Alta en 6/6 rubros' },
      { control: 'Scorecard', threshold: 'Firmado' },
      { control: 'Repositorio/historia', threshold: 'Aprobados' },
      { control: 'README/URLs', threshold: 'Aprobados' },
      { control: 'Demo rehearsal', threshold: 'PASS' },
      { control: 'Demo contingency', threshold: 'Preparada' },
      { control: 'Defectos P0/P1', threshold: '0' },
      { control: 'P2', threshold: 'Cerrados o aceptados' },
      { control: 'Disqualifiers', threshold: '0' },
      { control: 'Decisión', threshold: 'ACCEPTED' },
      { control: 'Paquete final', threshold: 'Completo' },
      { control: 'Handoff etapa 9', threshold: 'Completo' },
    ],
    states: ['PASS', 'FAIL'],
  },
]);

export const STAGE8_CATALOG = deepFreeze({
  schemaVersion: 1,
  stage: 8,
  kind: 'STAGE8_ACCEPTANCE_CATALOG',
  artifacts: STAGE8_ARTIFACTS,
  evidence: STAGE8_EVIDENCE,
  cases: STAGE8_CASES,
  auditControls: STAGE8_AUDIT_CONTROLS,
  gates: STAGE8_GATE_DEFINITIONS,
});

export const STAGE8_CATALOG_SHA256 = objectSha256(STAGE8_CATALOG);
const STAGE8_EXPECTED_CATALOG_SHA256 =
  '716a6091bac2569d6ae5da84e25066f5603feee384fc096adae3b154a0c6532d';

const STAGE7_REPORT_HEADINGS = [
  'Resumen ejecutivo',
  'Estado de entrada y GATE-E6-03',
  'Release ID, SHA, tag y checksums',
  'Autorizaciones y ventana',
  'Cuenta, región e identidad',
  'Toolchain y bootstrap',
  'IaC synth, tests, diff y drift',
  'IAM/OIDC',
  'Configuración y secretos',
  'DataStack y seed',
  'ApiStack y Lambda',
  'Reconciliador',
  'Observabilidad y presupuesto',
  'WebStack, S3 y CloudFront',
  'Dominio, TLS, CORS y headers',
  'Pipeline de release',
  'Smoke post-deploy',
  'Validación sandbox',
  'Seguridad real',
  'Rendimiento y accesibilidad focal',
  'Rollback frontend',
  'Rollback API/datos',
  'Re-promoción y smoke final',
  'Repositorio público y README',
  'Release notes',
  'Evidencias y trazabilidad',
  'Scorecard de rúbrica',
  'Riesgos, incidentes y desviaciones',
  'Cleanup y coste residual',
  'Evaluación GATE-E7-01',
  'Evaluación GATE-E7-02',
  'Evaluación GATE-E7-03',
  'Handoff a etapa 8',
];

export const STAGE8_REPORT_HEADINGS = deepFreeze([
  'Resumen ejecutivo',
  'Estado de entrada y GATE-E7-03',
  'Carta de aceptación',
  'Release ID, SHAs, tag y checksums',
  'Roles, entorno y autorizaciones',
  'Verificación independiente de URLs',
  'Repositorio público, historial y secretos',
  'README',
  'Pasada black-box',
  'Flujo de cinco pasos',
  'Producto y stock',
  'Tarjeta y entrega',
  'Resumen y cotización',
  'Transacción y sandbox',
  'Approved/declined/error/unknown',
  'Recuperación e idempotencia',
  'API y OpenAPI',
  'Datos e invariantes',
  'Pruebas y cobertura',
  'Responsive y browsers',
  'Accesibilidad',
  'Imágenes y rendimiento',
  'Seguridad y privacidad',
  'Despliegue cloud',
  'Clean code',
  'Hexagonal y ROP',
  'Scorecard base',
  'Scorecard bonus',
  'Disqualifiers y originalidad',
  'Defectos, riesgos y desviaciones',
  'Demo rehearsal',
  'Paquete final',
  'Evaluación GATE-E8-01',
  'Evaluación GATE-E8-02',
  'Evaluación GATE-E8-03',
  'Decisión de aceptación',
  'Handoff a etapa 9',
]);

export class Stage8ContractError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage8ContractError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage8ContractError(code);
};

const plainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  plainObject(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
const exactIdentity = (left, right) =>
  left.releaseId === right.releaseId &&
  left.candidateSha === right.candidateSha &&
  left.releaseTag === right.releaseTag;
const exactGateSet = (value, gateNames, expected) =>
  exactKeys(value, gateNames) && gateNames.every((gate) => value[gate] === expected);
const validStage8GateStatuses = (value) =>
  exactKeys(value, E8_GATES) &&
  ['NOT_EVALUATED', 'PASS', 'FAIL'].includes(value['GATE-E8-01']) &&
  ['NOT_EVALUATED', 'PASS', 'FAIL', 'BLOCKED_EXTERNAL'].includes(value['GATE-E8-02']) &&
  ['NOT_EVALUATED', 'PASS', 'FAIL', 'BLOCKED_EXTERNAL'].includes(value['GATE-E8-03']);
const finalizationReadyGates = (value) =>
  exactKeys(value, E8_GATES) &&
  value['GATE-E8-01'] === 'PASS' &&
  value['GATE-E8-02'] === 'PASS' &&
  value['GATE-E8-03'] === 'BLOCKED_EXTERNAL';
const validUtc = (value) =>
  typeof value === 'string' && ISO_UTC.test(value) && !Number.isNaN(Date.parse(value));
const validHttpsUrl = (value) => {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === 'https:' &&
      parsed.username === '' &&
      parsed.password === '' &&
      parsed.hash === '' &&
      parsed.hostname.length > 0
    );
  } catch {
    return false;
  }
};
const validUrls = (value) =>
  exactKeys(value, URL_KEYS) && URL_KEYS.every((key) => validHttpsUrl(value[key]));
const validEvidencePath = (value) =>
  typeof value === 'string' &&
  value.length >= 3 &&
  value.length <= 512 &&
  /^[A-Za-z0-9][A-Za-z0-9._/-]*$/u.test(value) &&
  !value.startsWith('stage8-finalization/') &&
  !value.includes('//') &&
  value.split('/').every((segment) => segment !== '.' && segment !== '..');
const validEvidenceIds = (value) =>
  Array.isArray(value) &&
  value.length > 0 &&
  value.length <= STAGE8_EVIDENCE.length &&
  new Set(value).size === value.length &&
  value.every((id) => /^EVD-E8-(?:0[1-9]|[1-3][0-9]|4[0-8])$/u.test(id));

const sourceBuffer = (source, label) => {
  if (!(typeof source === 'string' || source instanceof Uint8Array))
    fail(`${label}_SOURCE_MISSING`);
  const buffer = typeof source === 'string' ? Buffer.from(source) : Buffer.from(source);
  if (buffer.length === 0 || buffer.length > 16 * 1024 * 1024) fail(`${label}_SOURCE_SIZE_INVALID`);
  return buffer;
};

const parseJson = (source, label) => {
  const buffer = sourceBuffer(source, label);
  try {
    return { value: parseStrictJsonSource(buffer, { scanForbiddenData: false }), buffer };
  } catch {
    fail(`${label}_JSON_INVALID`);
  }
};

const assertNoObviousSensitiveMaterial = (source, label) => {
  const text = sourceBuffer(source, label).toString('utf8');
  const forbidden = [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/u,
    /\bAuthorization\s*:\s*(?:Basic|Bearer)\s+[A-Za-z0-9._~+/=-]{8,}/iu,
    /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]{8,}/iu,
    /\b(?:prv|pub)_(?:live|test)_[A-Za-z0-9_-]{8,}/iu,
    /"(?:pan|cvc|cvv|password|secret|privateKey|accessToken)"\s*:\s*"[^"\r\n]{4,}"/iu,
  ];
  if (forbidden.some((pattern) => pattern.test(text))) fail(`${label}_SENSITIVE_MATERIAL_DETECTED`);
};

const validateNotApplicableApproval = (source, { row, intake }) => {
  const parsed = parseJson(source, `E8_EVIDENCE_${row.id}_APPROVAL`);
  const value = parsed.value;
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'acceptanceId',
      'evidenceId',
      'release',
      'ownerAlias',
      'approvedByAlias',
      'approvedAtUtc',
      'reason',
      'containsSensitiveData',
      'approvalSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 8 ||
    value.kind !== 'STAGE8_NOT_APPLICABLE_APPROVAL' ||
    value.status !== 'APPROVED' ||
    value.acceptanceId !== intake.acceptanceId ||
    value.evidenceId !== row.id ||
    canonicalJson(value.release) !== canonicalJson(intake.release) ||
    value.ownerAlias !== row.ownerAlias ||
    !ALIAS.test(value.approvedByAlias ?? '') ||
    value.approvedByAlias === value.ownerAlias ||
    value.approvedAtUtc !== row.capturedAtUtc ||
    !validUtc(value.approvedAtUtc) ||
    !validDocumentationReason(value.reason) ||
    value.containsSensitiveData !== false
  ) {
    fail('E8_EVIDENCE_NOT_APPLICABLE_APPROVAL_INVALID');
  }
  const body = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== 'approvalSha256'),
  );
  if (value.approvalSha256 !== objectSha256(body)) {
    fail('E8_EVIDENCE_NOT_APPLICABLE_APPROVAL_INVALID');
  }
};

const listEvidenceFiles = (root) => {
  const files = [];
  const visit = (directory, prefix) => {
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      fail('E8_EVIDENCE_ROOT_READ_INVALID');
    }
    for (const entry of entries.toSorted((left, right) => left.name.localeCompare(right.name))) {
      const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      const absolute = path.join(directory, entry.name);
      let status;
      try {
        status = lstatSync(absolute);
      } catch {
        fail('E8_EVIDENCE_ROOT_READ_INVALID');
      }
      if (status.isSymbolicLink()) fail('E8_EVIDENCE_PATH_ALIAS_INVALID');
      if (status.isDirectory()) visit(absolute, relative);
      else if (status.isFile()) files.push(relative);
      else fail('E8_EVIDENCE_PATH_TYPE_INVALID');
    }
  };
  visit(root, '');
  return files;
};

const readStage8EvidenceInventory = ({ evidenceRoot, assessment, intake }) => {
  if (typeof evidenceRoot !== 'string' || evidenceRoot.length === 0) {
    fail('E8_EVIDENCE_ROOT_MISSING');
  }
  const resolvedRoot = path.resolve(evidenceRoot);
  let rootStatus;
  let realRoot;
  try {
    rootStatus = lstatSync(resolvedRoot);
    realRoot = realpathSync(resolvedRoot);
  } catch {
    fail('E8_EVIDENCE_ROOT_INVALID');
  }
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) {
    fail('E8_EVIDENCE_ROOT_INVALID');
  }
  const rowsWithMaterial = assessment.evidence.filter(({ status }) =>
    ['VERIFIED_FULL', 'NOT_APPLICABLE_APPROVED'].includes(status),
  );
  if (
    rowsWithMaterial.length !== STAGE8_EVIDENCE.length ||
    new Set(rowsWithMaterial.map(({ sourcePath }) => sourcePath)).size !== rowsWithMaterial.length
  ) {
    fail('E8_EVIDENCE_PATH_SET_INVALID');
  }
  const expectedPaths = rowsWithMaterial.map(({ sourcePath }) => sourcePath).toSorted();
  const observedPaths = listEvidenceFiles(realRoot).toSorted();
  if (canonicalJson(observedPaths) !== canonicalJson(expectedPaths)) {
    fail('E8_EVIDENCE_PATH_SET_INVALID');
  }
  let totalBytes = 0;
  const inventory = rowsWithMaterial.map((row) => {
    if (!validEvidencePath(row.sourcePath)) fail('E8_EVIDENCE_PATH_INVALID');
    const segments = row.sourcePath.split('/');
    let current = realRoot;
    for (const [index, segment] of segments.entries()) {
      current = path.join(current, segment);
      let status;
      try {
        status = lstatSync(current);
      } catch {
        fail('E8_EVIDENCE_FILE_MISSING');
      }
      if (status.isSymbolicLink()) fail('E8_EVIDENCE_PATH_ALIAS_INVALID');
      if (index < segments.length - 1 ? !status.isDirectory() : !status.isFile()) {
        fail('E8_EVIDENCE_PATH_TYPE_INVALID');
      }
    }
    let realFilename;
    let bytes;
    try {
      realFilename = realpathSync(current);
      bytes = readFileSync(realFilename);
    } catch {
      fail('E8_EVIDENCE_FILE_READ_INVALID');
    }
    const containmentPrefix = realRoot.endsWith(path.sep) ? realRoot : `${realRoot}${path.sep}`;
    if (!realFilename.startsWith(containmentPrefix)) fail('E8_EVIDENCE_PATH_ESCAPE');
    if (bytes.length === 0 || bytes.length > MAX_EVIDENCE_FILE_BYTES) {
      fail('E8_EVIDENCE_FILE_SIZE_INVALID');
    }
    totalBytes += bytes.length;
    if (totalBytes > MAX_EVIDENCE_TOTAL_BYTES) fail('E8_EVIDENCE_TOTAL_SIZE_INVALID');
    assertNoObviousSensitiveMaterial(bytes, `E8_EVIDENCE_${row.id}`);
    if (rawSha256(bytes) !== row.rawSha256) fail('E8_EVIDENCE_FILE_SHA256_MISMATCH');
    if (row.status === 'NOT_APPLICABLE_APPROVED') {
      validateNotApplicableApproval(bytes, {
        row,
        intake: { ...intake, acceptanceId: assessment.acceptanceId },
      });
    }
    return {
      id: row.id,
      status: row.status,
      path: row.sourcePath,
      rawSha256: row.rawSha256,
      bytes: bytes.length,
    };
  });
  return deepFreeze({
    inventory,
    inventorySha256: objectSha256(inventory),
    totalBytes,
  });
};

const assertCatalog = () => {
  const specifications = [
    [STAGE8_ARTIFACTS, 'ART-ACC', 16],
    [STAGE8_EVIDENCE, 'EVD-E8', 48],
    [STAGE8_CASES, 'ACC-TC', 32],
    [STAGE8_AUDIT_CONTROLS, 'ACCAUD', 72],
  ];
  for (const [catalog, prefix, count] of specifications) {
    assert.equal(catalog.length, count);
    assert.equal(new Set(catalog.map(({ id }) => id)).size, count);
    assert.deepEqual(
      catalog.map(({ id }) => id),
      Array.from(
        { length: count },
        (_, index) => `${prefix}-${String(index + 1).padStart(2, '0')}`,
      ),
    );
  }
  assert.deepEqual(
    STAGE8_GATE_DEFINITIONS.map(({ id }) => id),
    E8_GATES,
  );
  assert.deepEqual(
    STAGE8_ARTIFACT_EVIDENCE_BINDINGS.map(({ id }) => id),
    STAGE8_ARTIFACTS.map(({ id }) => id),
  );
  assert.equal(
    new Set(STAGE8_ARTIFACT_EVIDENCE_BINDINGS.flatMap(({ evidenceIds: ids }) => ids)).size,
    STAGE8_EVIDENCE.length,
  );
  assert.equal(STAGE8_CATALOG_SHA256, STAGE8_EXPECTED_CATALOG_SHA256);
};

const validDocumentationPath = (value) =>
  value === 'README.md' ||
  (typeof value === 'string' &&
    /^docs\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\.md$/u.test(value) &&
    !value.includes('//') &&
    value.split('/').every((segment) => segment !== '.' && segment !== '..'));

const validDocumentationReason = (value) =>
  typeof value === 'string' &&
  value.trim() === value &&
  value.length >= 12 &&
  value.length <= 500 &&
  [...value].every((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint > 31 && codePoint !== 127;
  });

const validateDocumentationAuthority = ({ source, trust, releaseManifestRawSha256 }) => {
  const sameCommit = trust.runtimeSha === trust.submissionSha;
  if (sameCommit) {
    if (
      trust.documentationAuthorityRawSha256 !== null ||
      trust.documentationAuthoritySha256 !== null ||
      source !== undefined
    ) {
      fail('E8_DOCUMENTATION_AUTHORITY_UNEXPECTED');
    }
    return deepFreeze({ mode: 'SAME_COMMIT', authority: null });
  }
  if (
    !SHA256.test(trust.documentationAuthorityRawSha256 ?? '') ||
    !SHA256.test(trust.documentationAuthoritySha256 ?? '') ||
    source === undefined
  ) {
    fail('E8_DOCUMENTATION_AUTHORITY_MISSING');
  }
  assertNoObviousSensitiveMaterial(source, 'E8_DOCUMENTATION_AUTHORITY');
  const parsed = parseJson(source, 'E8_DOCUMENTATION_AUTHORITY');
  const value = parsed.value;
  if (
    rawSha256(parsed.buffer) !== trust.documentationAuthorityRawSha256 ||
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'fromSha',
      'toSha',
      'changedPaths',
      'ownerAlias',
      'approvedByAlias',
      'approvedAtUtc',
      'reason',
      'sourceHashes',
      'containsSensitiveData',
      'authoritySha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 8 ||
    value.kind !== 'STAGE8_DOCUMENTATION_COMMIT_AUTHORITY' ||
    value.status !== 'APPROVED' ||
    value.fromSha !== trust.runtimeSha ||
    value.toSha !== trust.submissionSha ||
    value.fromSha === value.toSha ||
    !Array.isArray(value.changedPaths) ||
    value.changedPaths.length === 0 ||
    value.changedPaths.length > 128 ||
    new Set(value.changedPaths).size !== value.changedPaths.length ||
    canonicalJson(value.changedPaths) !== canonicalJson([...value.changedPaths].toSorted()) ||
    value.changedPaths.some((changedPath) => !validDocumentationPath(changedPath)) ||
    !ALIAS.test(value.ownerAlias ?? '') ||
    !ALIAS.test(value.approvedByAlias ?? '') ||
    value.ownerAlias === value.approvedByAlias ||
    !validUtc(value.approvedAtUtc) ||
    !validDocumentationReason(value.reason) ||
    !exactKeys(value.sourceHashes, [
      'commitMetadataRawSha256',
      'changedPathsRawSha256',
      'approvalRawSha256',
      'updatedManifestRawSha256',
    ]) ||
    !Object.values(value.sourceHashes).every((digest) => SHA256.test(digest ?? '')) ||
    value.sourceHashes.updatedManifestRawSha256 !== releaseManifestRawSha256 ||
    value.containsSensitiveData !== false
  ) {
    fail('E8_DOCUMENTATION_AUTHORITY_INVALID');
  }
  const body = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== 'authoritySha256'),
  );
  if (
    value.authoritySha256 !== objectSha256(body) ||
    value.authoritySha256 !== trust.documentationAuthoritySha256
  ) {
    fail('E8_DOCUMENTATION_AUTHORITY_SHA256_INVALID');
  }
  return deepFreeze({
    mode: 'DOCUMENTATION_ONLY_APPROVED',
    authority: { ...value, authorityRawSha256: rawSha256(parsed.buffer) },
  });
};

const validDocumentationCommit = (value, runtimeSha, submissionSha) => {
  if (!exactKeys(value, ['mode', 'authority'])) return false;
  if (runtimeSha === submissionSha) {
    return value.mode === 'SAME_COMMIT' && value.authority === null;
  }
  const authority = value.authority;
  if (
    value.mode !== 'DOCUMENTATION_ONLY_APPROVED' ||
    !plainObject(authority) ||
    !exactKeys(authority, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'fromSha',
      'toSha',
      'changedPaths',
      'ownerAlias',
      'approvedByAlias',
      'approvedAtUtc',
      'reason',
      'sourceHashes',
      'containsSensitiveData',
      'authoritySha256',
      'authorityRawSha256',
    ]) ||
    authority.schemaVersion !== 1 ||
    authority.stage !== 8 ||
    authority.kind !== 'STAGE8_DOCUMENTATION_COMMIT_AUTHORITY' ||
    authority.status !== 'APPROVED' ||
    authority.fromSha !== runtimeSha ||
    authority.toSha !== submissionSha ||
    !SHA256.test(authority.authorityRawSha256 ?? '') ||
    !SHA256.test(authority.authoritySha256 ?? '') ||
    !Array.isArray(authority.changedPaths) ||
    authority.changedPaths.length === 0 ||
    authority.changedPaths.length > 128 ||
    new Set(authority.changedPaths).size !== authority.changedPaths.length ||
    canonicalJson(authority.changedPaths) !==
      canonicalJson([...authority.changedPaths].toSorted()) ||
    authority.changedPaths.some((changedPath) => !validDocumentationPath(changedPath)) ||
    !ALIAS.test(authority.ownerAlias ?? '') ||
    !ALIAS.test(authority.approvedByAlias ?? '') ||
    authority.ownerAlias === authority.approvedByAlias ||
    !validUtc(authority.approvedAtUtc) ||
    !validDocumentationReason(authority.reason) ||
    !exactKeys(authority.sourceHashes, [
      'commitMetadataRawSha256',
      'changedPathsRawSha256',
      'approvalRawSha256',
      'updatedManifestRawSha256',
    ]) ||
    !Object.values(authority.sourceHashes).every((digest) => SHA256.test(digest ?? '')) ||
    authority.containsSensitiveData !== false
  ) {
    return false;
  }
  try {
    const { authorityRawSha256, ...sourceValue } = authority;
    const body = Object.fromEntries(
      Object.entries(sourceValue).filter(([key]) => key !== 'authoritySha256'),
    );
    return authorityRawSha256.length === 64 && sourceValue.authoritySha256 === objectSha256(body);
  } catch {
    return false;
  }
};

export const validateStage8TrustAnchor = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'releaseManifestRawSha256',
      'closeoutRawSha256',
      'releaseId',
      'runtimeSha',
      'submissionSha',
      'documentationAuthorityRawSha256',
      'documentationAuthoritySha256',
      'tag',
      'urls',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 8 ||
    value.kind !== 'STAGE8_E7_TRUST_ANCHOR' ||
    !SHA256.test(value.releaseManifestRawSha256 ?? '') ||
    !SHA256.test(value.closeoutRawSha256 ?? '') ||
    !RELEASE_ID.test(value.releaseId ?? '') ||
    !SHA.test(value.runtimeSha ?? '') ||
    !SHA.test(value.submissionSha ?? '') ||
    !(
      (value.runtimeSha === value.submissionSha &&
        value.documentationAuthorityRawSha256 === null &&
        value.documentationAuthoritySha256 === null) ||
      (value.runtimeSha !== value.submissionSha &&
        SHA256.test(value.documentationAuthorityRawSha256 ?? '') &&
        SHA256.test(value.documentationAuthoritySha256 ?? ''))
    ) ||
    !RELEASE_TAG.test(value.tag ?? '') ||
    !validUrls(value.urls) ||
    value.containsSensitiveData !== false
  ) {
    fail('E8_E7_TRUST_ANCHOR_INVALID');
  }
  return value;
};

const validateManifest = (value, trust, documentationCommit) => {
  const keys = [
    'schemaVersion',
    'stage',
    'kind',
    'status',
    'scope',
    'candidateSha',
    'runtimeSha',
    'submissionSha',
    'releaseId',
    'releaseTag',
    'generatedAtUtc',
    'ownerAlias',
    'releaseMode',
    'authorities',
    'contentBindings',
    'artifacts',
    'evidence',
    'gates',
    'publication',
    'rollback',
    'urls',
    'nextStage',
    'containsSensitiveData',
    'manifestSha256',
  ];
  if (
    !exactKeys(value, keys) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_FINAL_RELEASE_MANIFEST' ||
    value.status !== 'RELEASED' ||
    value.scope !== 'full' ||
    value.releaseMode !== 'VERSIONED_UPDATE' ||
    value.releaseId !== trust.releaseId ||
    value.candidateSha !== trust.runtimeSha ||
    value.runtimeSha !== value.candidateSha ||
    value.runtimeSha !== trust.runtimeSha ||
    value.submissionSha !== trust.submissionSha ||
    !validDocumentationCommit(documentationCommit, value.runtimeSha, value.submissionSha) ||
    value.releaseTag !== trust.tag ||
    !validUtc(value.generatedAtUtc) ||
    !ALIAS.test(value.ownerAlias ?? '') ||
    !exactGateSet(value.gates, E7_GATES, 'PASS') ||
    !exactKeys(value.artifacts, ['verified', 'total']) ||
    value.artifacts.verified !== 20 ||
    value.artifacts.total !== 20 ||
    !exactKeys(value.evidence, ['pass', 'total']) ||
    value.evidence.pass !== 57 ||
    value.evidence.total !== 57 ||
    value.nextStage !== 8 ||
    value.containsSensitiveData !== false ||
    !validUrls(value.urls) ||
    canonicalJson(value.urls) !== canonicalJson(trust.urls)
  ) {
    fail('E8_E7_MANIFEST_INVALID');
  }
  if (
    !exactKeys(value.authorities, [
      'stage6CloseoutSha256',
      'jobResultsSha256',
      'provenanceLedgerSha256',
      'evidenceIndexSha256',
      'gateEvaluationSha256',
      'scorecardSha256',
      'operationsRunbookSha256',
      'handoffSha256',
      'executedReportSha256',
    ]) ||
    !Object.values(value.authorities).every((digest) => SHA256.test(digest ?? '')) ||
    !exactKeys(value.contentBindings, [
      'stage6CloseoutSha256',
      'jobResultsSha256',
      'provenanceLedgerSha256',
      'evidenceIndexSha256',
      'gateEvaluationSha256',
      'scorecardSha256',
      'operationsRunbookSha256',
      'handoffSha256',
    ]) ||
    !Object.values(value.contentBindings).every((digest) => SHA256.test(digest ?? ''))
  ) {
    fail('E8_E7_MANIFEST_BINDINGS_INVALID');
  }
  if (
    !exactKeys(value.publication, [
      'releaseUrl',
      'readmeCommitSha',
      'repositoryPublic',
      'urlsVerified',
      'proofRawSha256',
      'proofObjectSha256',
    ]) ||
    value.publication.readmeCommitSha !== trust.submissionSha ||
    value.publication.readmeCommitSha !== value.submissionSha ||
    value.publication.repositoryPublic !== true ||
    value.publication.urlsVerified !== true ||
    value.publication.releaseUrl !== `${value.urls.repository}/releases/tag/${value.releaseTag}` ||
    !SHA256.test(value.publication.proofRawSha256 ?? '') ||
    !SHA256.test(value.publication.proofObjectSha256 ?? '') ||
    !exactKeys(value.rollback, [
      'predecessorManifestSha256',
      'completionRawSha256',
      'completionObjectSha256',
      'completionEnvelopeSha256',
    ]) ||
    !Object.values(value.rollback).every((digest) => SHA256.test(digest ?? ''))
  ) {
    fail('E8_E7_MANIFEST_RELEASE_PROOF_INVALID');
  }
  const body = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== 'manifestSha256'),
  );
  if (!SHA256.test(value.manifestSha256 ?? '') || value.manifestSha256 !== objectSha256(body)) {
    fail('E8_E7_MANIFEST_CANONICAL_SHA256_INVALID');
  }
  return value;
};

const validE7Rows = (items, catalog, kind, allowedStatuses, ownerAlias, validatedAtUtc) => {
  if (
    !Array.isArray(items) ||
    items.length !== catalog.length ||
    items.some(
      (item, index) =>
        !plainObject(item) ||
        item.id !== catalog[index].id ||
        item.name !== catalog[index].name ||
        !allowedStatuses.includes(item.status) ||
        item.ownerAlias !== ownerAlias ||
        item.validatedAtUtc !== validatedAtUtc,
    )
  ) {
    return false;
  }
  try {
    for (const item of items) validateStage7ProvenanceRow(item, { kind });
    return true;
  } catch {
    return false;
  }
};

const validE7SourceBindings = (value) => {
  if (
    !exactKeys(
      value,
      STAGE7_LEDGER_SOURCE_BINDING_SPECS.map(({ key }) => key),
    )
  ) {
    return false;
  }
  return STAGE7_LEDGER_SOURCE_BINDING_SPECS.every(({ key, basename }) => {
    const binding = value[key];
    return (
      exactKeys(binding, [
        'status',
        'basename',
        'path',
        'artifactName',
        'producerJob',
        'rawSha256',
        'objectSha256',
      ]) &&
      binding.status === 'BOUND' &&
      binding.basename === basename &&
      typeof binding.path === 'string' &&
      binding.path.replaceAll('\\', '/').endsWith(`/${basename}`) &&
      typeof binding.artifactName === 'string' &&
      binding.artifactName.length > 0 &&
      typeof binding.producerJob === 'string' &&
      binding.producerJob.length > 0 &&
      SHA256.test(binding.rawSha256 ?? '') &&
      SHA256.test(binding.objectSha256 ?? '')
    );
  });
};

const validateLedger = (value, manifest, handoff) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'generatedAtUtc',
      'ownerAlias',
      'entryGate',
      'catalogSha256',
      'counts',
      'gates',
      'artifacts',
      'evidence',
      'sourceBindings',
      'handoffContentSha256',
      'nextStage',
      'containsSensitiveData',
      'ledgerSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_PROVENANCE_LEDGER' ||
    value.status !== 'VERIFIED' ||
    value.scope !== 'full' ||
    !exactIdentity(value, manifest) ||
    value.generatedAtUtc !== manifest.generatedAtUtc ||
    value.ownerAlias !== manifest.ownerAlias ||
    value.entryGate !== 'PASS' ||
    value.catalogSha256 !==
      objectSha256({ artifacts: STAGE7_SOURCE_ARTIFACTS, evidence: STAGE7_SOURCE_EVIDENCE }) ||
    !exactKeys(value.counts, ['artifacts', 'evidence']) ||
    !exactKeys(value.counts.artifacts, ['verified', 'total']) ||
    value.counts.artifacts.verified !== 20 ||
    value.counts.artifacts.total !== 20 ||
    !exactKeys(value.counts.evidence, ['pass', 'total']) ||
    value.counts.evidence.pass !== 57 ||
    value.counts.evidence.total !== 57 ||
    !exactGateSet(value.gates, E7_GATES, 'PASS') ||
    !validE7Rows(
      value.artifacts,
      STAGE7_SOURCE_ARTIFACTS,
      'artifact',
      ['VERIFIED', 'NOT_APPLICABLE_APPROVED'],
      value.ownerAlias,
      value.generatedAtUtc,
    ) ||
    !validE7Rows(
      value.evidence,
      STAGE7_SOURCE_EVIDENCE,
      'evidence',
      ['PASS', 'NOT_APPLICABLE_APPROVED'],
      value.ownerAlias,
      value.generatedAtUtc,
    ) ||
    !validE7SourceBindings(value.sourceBindings) ||
    value.handoffContentSha256 !== objectSha256(handoff) ||
    value.nextStage !== 8 ||
    value.containsSensitiveData !== false
  ) {
    fail('E8_E7_LEDGER_INVALID');
  }
  const body = Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'ledgerSha256'));
  if (!SHA256.test(value.ledgerSha256 ?? '') || value.ledgerSha256 !== objectSha256(body)) {
    fail('E8_E7_LEDGER_CANONICAL_SHA256_INVALID');
  }
  return value;
};

const validateHandoff = (value, manifest) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'ownerAlias',
      'generatedAtUtc',
      'itemCount',
      'readyCount',
      'items',
      'nextStage',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_HANDOFF_TO_STAGE8' ||
    value.status !== 'READY_FOR_STAGE8' ||
    value.scope !== 'full' ||
    !exactIdentity(value, manifest) ||
    value.ownerAlias !== manifest.ownerAlias ||
    value.generatedAtUtc !== manifest.generatedAtUtc ||
    value.itemCount !== 37 ||
    value.readyCount !== 37 ||
    !Array.isArray(value.items) ||
    value.items.length !== 37 ||
    value.items.some((item, index) => {
      if (
        !exactKeys(item, ['number', 'label', 'status', 'dependencyIds', 'sources']) ||
        item.number !== index + 1 ||
        typeof item.label !== 'string' ||
        item.label.length < 3 ||
        item.label.length > 160 ||
        item.status !== 'READY' ||
        !Array.isArray(item.dependencyIds) ||
        item.dependencyIds.length === 0 ||
        new Set(item.dependencyIds).size !== item.dependencyIds.length ||
        item.dependencyIds.some(
          (id) =>
            !/^(?:ART-REL-(?:0[1-9]|1[0-9]|20)|EVD-E7-(?:0[1-9]|[1-4][0-9]|5[0-7]))$/u.test(id),
        ) ||
        !Array.isArray(item.sources) ||
        item.sources.length === 0
      ) {
        return true;
      }
      try {
        for (const source of item.sources) validateStage7SourceReference(source);
        return false;
      } catch {
        return true;
      }
    }) ||
    value.nextStage !== 8 ||
    value.containsSensitiveData !== false
  ) {
    fail('E8_E7_HANDOFF_INVALID');
  }
  return value;
};

const validStage7Index = (value) => {
  try {
    validateStage7Index(value);
    return exactGateSet(value.gates, E7_GATES, 'PASS');
  } catch {
    return false;
  }
};

const validateCloseout = (value, manifest, ledger) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'stage6RunId',
      'stage6ManifestSha256',
      'releaseMode',
      'updateReleaseSupported',
      'updateReleaseUnsupportedReason',
      'cloudFormationDrift',
      'authorizationLedger',
      'publication',
      'jobs',
      'index',
      'gates',
      'artifacts',
      'evidence',
      'releaseManifestSha256',
      'provenanceLedgerSha256',
      'nextStage',
      'mutationsPerformedByVerifier',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_CLOSEOUT' ||
    value.status !== 'RELEASED' ||
    !exactIdentity(value, manifest) ||
    value.releaseMode !== 'VERSIONED_UPDATE' ||
    value.updateReleaseSupported !== true ||
    value.updateReleaseUnsupportedReason !== null ||
    typeof value.stage6RunId !== 'string' ||
    value.stage6RunId.length < 8 ||
    !SHA256.test(value.stage6ManifestSha256 ?? '') ||
    !exactKeys(value.cloudFormationDrift, ['checked', 'criticalCount', 'status']) ||
    value.cloudFormationDrift.checked !== 4 ||
    value.cloudFormationDrift.criticalCount !== 0 ||
    value.cloudFormationDrift.status !== 'IN_SYNC' ||
    !plainObject(value.authorizationLedger) ||
    !Array.isArray(value.jobs) ||
    value.jobs.length === 0 ||
    new Set(value.jobs).size !== value.jobs.length ||
    value.jobs.some((job) => typeof job !== 'string' || job.length === 0) ||
    !exactGateSet(value.gates, E7_GATES, 'PASS') ||
    !validStage7Index(value.index) ||
    canonicalJson(value.artifacts) !== canonicalJson(manifest.artifacts) ||
    canonicalJson(value.evidence) !== canonicalJson(manifest.evidence) ||
    value.releaseManifestSha256 !== manifest.manifestSha256 ||
    value.provenanceLedgerSha256 !== ledger.ledgerSha256 ||
    value.nextStage !== 8 ||
    value.mutationsPerformedByVerifier !== 0 ||
    value.containsSensitiveData !== false ||
    !exactKeys(value.publication, [
      'releaseUrl',
      'readmeCommitSha',
      'repositoryPublic',
      'urlsVerified',
    ]) ||
    value.publication.readmeCommitSha !== manifest.publication.readmeCommitSha ||
    value.publication.releaseUrl !== manifest.publication.releaseUrl ||
    value.publication.repositoryPublic !== true ||
    value.publication.urlsVerified !== true
  ) {
    fail('E8_E7_CLOSEOUT_INVALID');
  }
  return value;
};

const validateExecutedReport = (source, manifest) => {
  const buffer = sourceBuffer(source, 'E8_E7_REPORT');
  const report = buffer.toString('utf8');
  if (
    buffer.length < 2_000 ||
    buffer.length > 256_000 ||
    !report.startsWith('# Etapa 7 — Release y despliegue (reporte ejecutado)\n') ||
    !report.includes(manifest.releaseId) ||
    !report.includes(manifest.candidateSha) ||
    !report.includes(manifest.releaseTag) ||
    /STATUS_BY_|PENDING_BY_|\bTODO\b|\bTBD\b/u.test(report)
  ) {
    fail('E8_E7_EXECUTED_REPORT_INVALID');
  }
  for (const [index, heading] of STAGE7_REPORT_HEADINGS.entries()) {
    const marker = `## ${index + 1}. ${heading}`;
    if (report.split(marker).length !== 2) fail('E8_E7_EXECUTED_REPORT_HEADING_INVALID');
  }
  return report;
};

export const validateStage7AcceptanceIntake = ({
  files,
  trustAnchor,
  documentationAuthoritySource,
}) => {
  assertCatalog();
  const trust = validateStage8TrustAnchor(trustAnchor);
  if (
    !exactKeys(files, ['report', 'manifest', 'ledger', 'closeout', 'handoff']) ||
    Object.values(files).some(
      (source) => !(typeof source === 'string' || source instanceof Uint8Array),
    )
  ) {
    fail('E8_E7_SOURCE_SET_INVALID');
  }
  for (const [name, source] of Object.entries(files)) {
    assertNoObviousSensitiveMaterial(source, `E8_E7_${name.toUpperCase()}`);
  }
  const manifestDocument = parseJson(files.manifest, 'E8_E7_MANIFEST');
  const ledgerDocument = parseJson(files.ledger, 'E8_E7_LEDGER');
  const closeoutDocument = parseJson(files.closeout, 'E8_E7_CLOSEOUT');
  const handoffDocument = parseJson(files.handoff, 'E8_E7_HANDOFF');

  if (rawSha256(manifestDocument.buffer) !== trust.releaseManifestRawSha256) {
    fail('E8_E7_MANIFEST_TRUST_ANCHOR_MISMATCH');
  }
  if (rawSha256(closeoutDocument.buffer) !== trust.closeoutRawSha256) {
    fail('E8_E7_CLOSEOUT_TRUST_ANCHOR_MISMATCH');
  }

  const documentationCommit = validateDocumentationAuthority({
    source: documentationAuthoritySource,
    trust,
    releaseManifestRawSha256: rawSha256(manifestDocument.buffer),
  });
  const manifest = validateManifest(manifestDocument.value, trust, documentationCommit);
  const handoff = validateHandoff(handoffDocument.value, manifest);
  const ledger = validateLedger(ledgerDocument.value, manifest, handoff);
  validateCloseout(closeoutDocument.value, manifest, ledger);

  if (rawSha256(ledgerDocument.buffer) !== manifest.authorities.provenanceLedgerSha256) {
    fail('E8_E7_LEDGER_RAW_SHA256_MISMATCH');
  }
  if (rawSha256(handoffDocument.buffer) !== manifest.authorities.handoffSha256) {
    fail('E8_E7_HANDOFF_RAW_SHA256_MISMATCH');
  }
  if (rawSha256(files.report) !== manifest.authorities.executedReportSha256) {
    fail('E8_E7_REPORT_RAW_SHA256_MISMATCH');
  }
  if (
    objectSha256(ledger) !== manifest.contentBindings.provenanceLedgerSha256 ||
    objectSha256(handoff) !== manifest.contentBindings.handoffSha256
  ) {
    fail('E8_E7_CANONICAL_BINDING_MISMATCH');
  }
  validateExecutedReport(files.report, manifest);

  const body = {
    schemaVersion: 1,
    stage: 8,
    kind: 'STAGE8_E7_ACCEPTANCE_INTAKE',
    intakeValidated: true,
    release: {
      releaseId: manifest.releaseId,
      runtimeSha: manifest.runtimeSha,
      submissionSha: manifest.submissionSha,
      tag: manifest.releaseTag,
      documentationCommit,
    },
    urls: manifest.urls,
    stage7Gates: manifest.gates,
    sourceBindings: {
      releaseManifestRawSha256: rawSha256(manifestDocument.buffer),
      releaseManifestObjectSha256: manifest.manifestSha256,
      closeoutRawSha256: rawSha256(closeoutDocument.buffer),
      provenanceLedgerRawSha256: rawSha256(ledgerDocument.buffer),
      provenanceLedgerObjectSha256: ledger.ledgerSha256,
      handoffRawSha256: rawSha256(handoffDocument.buffer),
      handoffObjectSha256: objectSha256(handoff),
      executedReportRawSha256: rawSha256(files.report),
    },
    stage7Counts: {
      artifacts: manifest.artifacts.total,
      evidence: manifest.evidence.total,
      handoffItems: handoff.itemCount,
    },
    stage7GeneratedAtUtc: manifest.generatedAtUtc,
    stage7OwnerAlias: manifest.ownerAlias,
    containsSensitiveData: false,
  };
  return deepFreeze({ ...body, intakeSha256: objectSha256(body) });
};

export const validateStage8IntakeResult = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'intakeValidated',
      'release',
      'urls',
      'stage7Gates',
      'sourceBindings',
      'stage7Counts',
      'stage7GeneratedAtUtc',
      'stage7OwnerAlias',
      'containsSensitiveData',
      'intakeSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 8 ||
    value.kind !== 'STAGE8_E7_ACCEPTANCE_INTAKE' ||
    value.intakeValidated !== true ||
    !exactKeys(value.release, [
      'releaseId',
      'runtimeSha',
      'submissionSha',
      'tag',
      'documentationCommit',
    ]) ||
    !RELEASE_ID.test(value.release.releaseId ?? '') ||
    !SHA.test(value.release.runtimeSha ?? '') ||
    !SHA.test(value.release.submissionSha ?? '') ||
    !validDocumentationCommit(
      value.release.documentationCommit,
      value.release.runtimeSha,
      value.release.submissionSha,
    ) ||
    !RELEASE_TAG.test(value.release.tag ?? '') ||
    !validUrls(value.urls) ||
    !exactGateSet(value.stage7Gates, E7_GATES, 'PASS') ||
    !plainObject(value.sourceBindings) ||
    Object.keys(value.sourceBindings).length !== 8 ||
    !Object.values(value.sourceBindings).every((digest) => SHA256.test(digest ?? '')) ||
    !exactKeys(value.stage7Counts, ['artifacts', 'evidence', 'handoffItems']) ||
    value.stage7Counts.artifacts !== 20 ||
    value.stage7Counts.evidence !== 57 ||
    value.stage7Counts.handoffItems !== 37 ||
    !validUtc(value.stage7GeneratedAtUtc) ||
    !ALIAS.test(value.stage7OwnerAlias ?? '') ||
    value.containsSensitiveData !== false
  ) {
    fail('E8_INTAKE_RESULT_INVALID');
  }
  const body = Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'intakeSha256'));
  if (value.intakeSha256 !== objectSha256(body)) fail('E8_INTAKE_RESULT_SHA256_INVALID');
  return value;
};

const initialGates = () => Object.fromEntries(E8_GATES.map((gate) => [gate, 'NOT_EVALUATED']));

export const createStage8AssessmentTemplate = (intake) => {
  validateStage8IntakeResult(intake);
  const body = {
    schemaVersion: 1,
    stage: 8,
    kind: 'STAGE8_EXECUTED_ASSESSMENT',
    acceptanceId: `acc-${intake.release.releaseId}`,
    release: intake.release,
    generatedAtUtc: null,
    artifacts: STAGE8_ARTIFACTS.map(({ id }) => ({ id, status: 'NOT_STARTED' })),
    evidence: STAGE8_EVIDENCE.map(({ id }) => ({
      id,
      status: 'NOT_STARTED',
      sourcePath: null,
      rawSha256: null,
      capturedAtUtc: null,
      ownerAlias: null,
    })),
    cases: STAGE8_CASES.map(({ id }) => ({
      id,
      result: 'NOT_EVALUATED',
      evidenceIds: [],
    })),
    auditControls: STAGE8_AUDIT_CONTROLS.map(({ id }) => ({
      id,
      result: 'NOT_EVALUATED',
      evidenceIds: [],
    })),
    gates: initialGates(),
    scorecard: {
      baseVerifiedPoints: 0,
      baseTotalPoints: 100,
      bonusVerifiedPoints: 0,
      bonusTotalPoints: 50,
      highConfidenceBaseRubrics: 0,
      signed: false,
    },
    quality: {
      openP0: 0,
      openP1: 0,
      openP2: 0,
      acceptedP2: 0,
      disqualifiers: 0,
      openCriticalRisks: 0,
    },
    demo: { rehearsal: 'NOT_STARTED', contingency: 'NOT_STARTED' },
    package: { complete: false, artifacts: 0, evidence: 0, cases: 0, auditControls: 0 },
    decision: 'PENDING',
    signatures: [],
    handoffReady: false,
    containsSensitiveData: false,
  };
  return deepFreeze({ ...body, assessmentSha256: objectSha256(body) });
};

const exactRows = (actual, catalog, field, allowed) =>
  Array.isArray(actual) &&
  actual.length === catalog.length &&
  actual.every(
    (row, index) =>
      exactKeys(row, ['id', field]) && row.id === catalog[index].id && allowed.includes(row[field]),
  );

const exactEvidenceRows = (actual) =>
  Array.isArray(actual) &&
  actual.length === STAGE8_EVIDENCE.length &&
  actual.every((row, index) => {
    if (
      !exactKeys(row, ['id', 'status', 'sourcePath', 'rawSha256', 'capturedAtUtc', 'ownerAlias']) ||
      row.id !== STAGE8_EVIDENCE[index].id ||
      ![
        'NOT_STARTED',
        'VERIFIED_FULL',
        'PARTIAL_RISK',
        'NOT_VERIFIED',
        'FAILED',
        'BLOCKED_EXTERNAL',
        'NOT_APPLICABLE_APPROVED',
        'DISQUALIFIER',
      ].includes(row.status)
    ) {
      return false;
    }
    const hasMaterial = row.status !== 'NOT_STARTED';
    return hasMaterial
      ? validEvidencePath(row.sourcePath) &&
          SHA256.test(row.rawSha256 ?? '') &&
          validUtc(row.capturedAtUtc) &&
          ALIAS.test(row.ownerAlias ?? '')
      : row.sourcePath === null &&
          row.rawSha256 === null &&
          row.capturedAtUtc === null &&
          row.ownerAlias === null;
  });

const exactBoundRows = (actual, catalog, field, allowed) =>
  Array.isArray(actual) &&
  actual.length === catalog.length &&
  actual.every(
    (row, index) =>
      exactKeys(row, ['id', field, 'evidenceIds']) &&
      row.id === catalog[index].id &&
      allowed.includes(row[field]) &&
      (row[field] === 'NOT_EVALUATED'
        ? Array.isArray(row.evidenceIds) && row.evidenceIds.length === 0
        : validEvidenceIds(row.evidenceIds)),
  );

const validAssessmentBindings = (assessment) => {
  const evidenceStatus = new Map(assessment.evidence.map(({ id, status }) => [id, status]));
  return (
    assessment.cases.every(
      ({ result, evidenceIds }) =>
        result !== 'PASS' || evidenceIds.every((id) => evidenceStatus.get(id) === 'VERIFIED_FULL'),
    ) &&
    assessment.auditControls.every(
      ({ result, evidenceIds }) =>
        result !== 'PASS' ||
        evidenceIds.every((id) =>
          ['VERIFIED_FULL', 'NOT_APPLICABLE_APPROVED'].includes(evidenceStatus.get(id)),
        ),
    )
  );
};

export const validateStage8Assessment = (value, intake) => {
  validateStage8IntakeResult(intake);
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'acceptanceId',
      'release',
      'generatedAtUtc',
      'artifacts',
      'evidence',
      'cases',
      'auditControls',
      'gates',
      'scorecard',
      'quality',
      'demo',
      'package',
      'decision',
      'signatures',
      'handoffReady',
      'containsSensitiveData',
      'assessmentSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 8 ||
    value.kind !== 'STAGE8_EXECUTED_ASSESSMENT' ||
    !ACCEPTANCE_ID.test(value.acceptanceId ?? '') ||
    canonicalJson(value.release) !== canonicalJson(intake.release) ||
    !(value.generatedAtUtc === null || validUtc(value.generatedAtUtc)) ||
    !exactRows(value.artifacts, STAGE8_ARTIFACTS, 'status', [
      'NOT_STARTED',
      'IN_PROGRESS',
      'VERIFIED',
      'FAILED',
      'BLOCKED_EXTERNAL',
      'CLOSED_OR_ACCEPTED',
      'REHEARSED',
      'READY',
      'ACCEPTED',
      'REJECTED',
      'NOT_APPLICABLE_APPROVED',
    ]) ||
    !exactEvidenceRows(value.evidence) ||
    !exactBoundRows(value.cases, STAGE8_CASES, 'result', [
      'NOT_EVALUATED',
      'PASS',
      'FAIL',
      'BLOCKED_EXTERNAL',
    ]) ||
    !exactBoundRows(value.auditControls, STAGE8_AUDIT_CONTROLS, 'result', [
      'NOT_EVALUATED',
      'PASS',
      'FAIL',
      'BLOCKED_EXTERNAL',
      'REVIEW_REQUIRED',
      'NOT_APPLICABLE_APPROVED',
    ]) ||
    !validStage8GateStatuses(value.gates) ||
    !exactKeys(value.scorecard, [
      'baseVerifiedPoints',
      'baseTotalPoints',
      'bonusVerifiedPoints',
      'bonusTotalPoints',
      'highConfidenceBaseRubrics',
      'signed',
    ]) ||
    !Number.isInteger(value.scorecard.baseVerifiedPoints) ||
    value.scorecard.baseVerifiedPoints < 0 ||
    value.scorecard.baseVerifiedPoints > 100 ||
    value.scorecard.baseTotalPoints !== 100 ||
    !Number.isInteger(value.scorecard.bonusVerifiedPoints) ||
    value.scorecard.bonusVerifiedPoints < 0 ||
    value.scorecard.bonusVerifiedPoints > 50 ||
    value.scorecard.bonusTotalPoints !== 50 ||
    !Number.isInteger(value.scorecard.highConfidenceBaseRubrics) ||
    value.scorecard.highConfidenceBaseRubrics < 0 ||
    value.scorecard.highConfidenceBaseRubrics > 6 ||
    typeof value.scorecard.signed !== 'boolean' ||
    !exactKeys(value.quality, [
      'openP0',
      'openP1',
      'openP2',
      'acceptedP2',
      'disqualifiers',
      'openCriticalRisks',
    ]) ||
    !Object.values(value.quality).every((count) => Number.isInteger(count) && count >= 0) ||
    value.quality.acceptedP2 > value.quality.openP2 ||
    !exactKeys(value.demo, ['rehearsal', 'contingency']) ||
    !['NOT_STARTED', 'PASS', 'FAIL', 'BLOCKED_EXTERNAL'].includes(value.demo.rehearsal) ||
    !['NOT_STARTED', 'READY', 'FAIL'].includes(value.demo.contingency) ||
    !exactKeys(value.package, ['complete', 'artifacts', 'evidence', 'cases', 'auditControls']) ||
    typeof value.package.complete !== 'boolean' ||
    !['artifacts', 'evidence', 'cases', 'auditControls'].every(
      (key) => Number.isInteger(value.package[key]) && value.package[key] >= 0,
    ) ||
    !['PENDING', 'ACCEPTED', 'REJECTED', 'RETURN_TO_STAGE', 'REVIEW_REQUIRED'].includes(
      value.decision,
    ) ||
    !Array.isArray(value.signatures) ||
    value.signatures.some(
      (signature) =>
        !exactKeys(signature, ['role', 'alias', 'signedAtUtc']) ||
        !['ACCEPTANCE_LEAD', 'OBSERVER'].includes(signature.role) ||
        !ALIAS.test(signature.alias ?? '') ||
        !validUtc(signature.signedAtUtc),
    ) ||
    typeof value.handoffReady !== 'boolean' ||
    value.containsSensitiveData !== false ||
    !validAssessmentBindings(value)
  ) {
    fail('E8_ASSESSMENT_INVALID');
  }
  const body = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== 'assessmentSha256'),
  );
  if (!SHA256.test(value.assessmentSha256 ?? '') || value.assessmentSha256 !== objectSha256(body)) {
    fail('E8_ASSESSMENT_SHA256_INVALID');
  }
  return value;
};

const exactAssessmentIdentity = (value, intake, assessment) =>
  value.acceptanceId === assessment.acceptanceId &&
  canonicalJson(value.release) === canonicalJson(intake.release);

export const validateStage8EvidenceAuthority = (value, { intake, assessment }) => {
  validateStage8IntakeResult(intake);
  validateStage8Assessment(assessment, intake);
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'acceptanceId',
      'release',
      'assessmentRawSha256',
      'assessmentSha256',
      'indexRawSha256',
      'indexSha256',
      'packageRawSha256',
      'packageSha256',
      'evidenceInventorySha256',
      'artifactBindingsSha256',
      'issuerAlias',
      'issuedAtUtc',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 8 ||
    value.kind !== 'STAGE8_EVIDENCE_AUTHORITY' ||
    !exactAssessmentIdentity(value, intake, assessment) ||
    ![
      'assessmentRawSha256',
      'assessmentSha256',
      'indexRawSha256',
      'indexSha256',
      'packageRawSha256',
      'packageSha256',
      'evidenceInventorySha256',
      'artifactBindingsSha256',
    ].every((key) => SHA256.test(value[key] ?? '')) ||
    value.assessmentSha256 !== assessment.assessmentSha256 ||
    value.artifactBindingsSha256 !== STAGE8_ARTIFACT_BINDINGS_SHA256 ||
    !ALIAS.test(value.issuerAlias ?? '') ||
    !validUtc(value.issuedAtUtc) ||
    value.containsSensitiveData !== false
  ) {
    fail('E8_EVIDENCE_AUTHORITY_INVALID');
  }
  return value;
};

const validateStage8EvidenceIndex = (value, { intake, assessment, evidenceInventory }) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'acceptanceId',
      'release',
      'generatedAtUtc',
      'entries',
      'evidenceInventory',
      'evidenceInventorySha256',
      'artifactBindings',
      'artifactBindingsSha256',
      'containsSensitiveData',
      'indexSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 8 ||
    value.kind !== 'STAGE8_EVIDENCE_INDEX' ||
    !exactAssessmentIdentity(value, intake, assessment) ||
    value.generatedAtUtc !== assessment.generatedAtUtc ||
    canonicalJson(value.entries) !== canonicalJson(assessment.evidence) ||
    canonicalJson(value.evidenceInventory) !== canonicalJson(evidenceInventory.inventory) ||
    value.evidenceInventorySha256 !== evidenceInventory.inventorySha256 ||
    canonicalJson(value.artifactBindings) !== canonicalJson(STAGE8_ARTIFACT_EVIDENCE_BINDINGS) ||
    value.artifactBindingsSha256 !== STAGE8_ARTIFACT_BINDINGS_SHA256 ||
    value.containsSensitiveData !== false ||
    !SHA256.test(value.indexSha256 ?? '')
  ) {
    fail('E8_EVIDENCE_INDEX_INVALID');
  }
  const body = Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'indexSha256'));
  if (value.indexSha256 !== objectSha256(body)) fail('E8_EVIDENCE_INDEX_SHA256_INVALID');
  return value;
};

const validateStage8EvidencePackage = (
  value,
  { intake, assessment, assessmentRawSha256, indexRawSha256, indexSha256, evidenceInventory },
) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'acceptanceId',
      'release',
      'generatedAtUtc',
      'assessmentRawSha256',
      'assessmentSha256',
      'indexRawSha256',
      'indexSha256',
      'evidenceInventory',
      'evidenceInventorySha256',
      'artifactBindings',
      'artifactBindingsSha256',
      'counts',
      'containsSensitiveData',
      'packageSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 8 ||
    value.kind !== 'STAGE8_EVIDENCE_PACKAGE' ||
    !exactAssessmentIdentity(value, intake, assessment) ||
    value.generatedAtUtc !== assessment.generatedAtUtc ||
    value.assessmentRawSha256 !== assessmentRawSha256 ||
    value.assessmentSha256 !== assessment.assessmentSha256 ||
    value.indexRawSha256 !== indexRawSha256 ||
    value.indexSha256 !== indexSha256 ||
    canonicalJson(value.evidenceInventory) !== canonicalJson(evidenceInventory.inventory) ||
    value.evidenceInventorySha256 !== evidenceInventory.inventorySha256 ||
    canonicalJson(value.artifactBindings) !== canonicalJson(STAGE8_ARTIFACT_EVIDENCE_BINDINGS) ||
    value.artifactBindingsSha256 !== STAGE8_ARTIFACT_BINDINGS_SHA256 ||
    !exactKeys(value.counts, ['artifacts', 'evidence', 'cases', 'auditControls']) ||
    value.counts.artifacts !== 16 ||
    value.counts.evidence !== 48 ||
    value.counts.cases !== 32 ||
    value.counts.auditControls !== 72 ||
    value.containsSensitiveData !== false ||
    !SHA256.test(value.packageSha256 ?? '')
  ) {
    fail('E8_EVIDENCE_PACKAGE_INVALID');
  }
  const body = Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'packageSha256'));
  if (value.packageSha256 !== objectSha256(body)) fail('E8_EVIDENCE_PACKAGE_SHA256_INVALID');
  return value;
};

export const validateStage8EvidenceMaterial = ({
  intake,
  assessment,
  assessmentSource,
  evidenceIndexSource,
  evidencePackageSource,
  evidenceAuthority,
  evidenceRoot,
}) => {
  validateStage8IntakeResult(intake);
  validateStage8Assessment(assessment, intake);
  if (
    assessmentSource === undefined ||
    evidenceIndexSource === undefined ||
    evidencePackageSource === undefined ||
    evidenceAuthority === undefined ||
    evidenceRoot === undefined
  ) {
    fail('E8_EVIDENCE_AUTHORITY_MISSING');
  }
  assertNoObviousSensitiveMaterial(assessmentSource, 'E8_ASSESSMENT_AUTHORITY');
  assertNoObviousSensitiveMaterial(evidenceIndexSource, 'E8_EVIDENCE_INDEX');
  assertNoObviousSensitiveMaterial(evidencePackageSource, 'E8_EVIDENCE_PACKAGE');
  const parsedAssessment = parseJson(assessmentSource, 'E8_ASSESSMENT_AUTHORITY');
  validateStage8Assessment(parsedAssessment.value, intake);
  if (canonicalJson(parsedAssessment.value) !== canonicalJson(assessment)) {
    fail('E8_ASSESSMENT_AUTHORITY_VALUE_MISMATCH');
  }
  const evidenceInventory = readStage8EvidenceInventory({ evidenceRoot, assessment, intake });
  const parsedIndex = parseJson(evidenceIndexSource, 'E8_EVIDENCE_INDEX');
  const index = validateStage8EvidenceIndex(parsedIndex.value, {
    intake,
    assessment,
    evidenceInventory,
  });
  const parsedPackage = parseJson(evidencePackageSource, 'E8_EVIDENCE_PACKAGE');
  const package_ = validateStage8EvidencePackage(parsedPackage.value, {
    intake,
    assessment,
    assessmentRawSha256: rawSha256(parsedAssessment.buffer),
    indexRawSha256: rawSha256(parsedIndex.buffer),
    indexSha256: index.indexSha256,
    evidenceInventory,
  });
  const authority = validateStage8EvidenceAuthority(evidenceAuthority, { intake, assessment });
  if (
    authority.assessmentRawSha256 !== rawSha256(parsedAssessment.buffer) ||
    authority.indexRawSha256 !== rawSha256(parsedIndex.buffer) ||
    authority.indexSha256 !== index.indexSha256 ||
    authority.packageRawSha256 !== rawSha256(parsedPackage.buffer) ||
    authority.packageSha256 !== package_.packageSha256 ||
    authority.evidenceInventorySha256 !== evidenceInventory.inventorySha256 ||
    authority.artifactBindingsSha256 !== STAGE8_ARTIFACT_BINDINGS_SHA256
  ) {
    fail('E8_EVIDENCE_AUTHORITY_HASH_MISMATCH');
  }
  return deepFreeze({
    assessment: parsedAssessment.value,
    index,
    package: package_,
    authority,
    evidenceInventory,
    evidenceAuthoritySha256: objectSha256(authority),
    packageEvidence: {
      rawSha256: rawSha256(parsedPackage.buffer),
      indexRawSha256: rawSha256(parsedIndex.buffer),
      evidenceInventorySha256: evidenceInventory.inventorySha256,
      artifactBindingsSha256: STAGE8_ARTIFACT_BINDINGS_SHA256,
      ...package_.counts,
    },
  });
};

const acceptedAssessment = (assessment) =>
  assessment.artifacts.every(
    ({ id, status }, index) =>
      id === STAGE8_ARTIFACTS[index].id && status === STAGE8_ARTIFACTS[index].acceptedState,
  ) &&
  assessment.evidence.every(({ status }) =>
    ['VERIFIED_FULL', 'NOT_APPLICABLE_APPROVED'].includes(status),
  ) &&
  assessment.cases.every(({ result }) => result === 'PASS') &&
  assessment.auditControls.every(({ result }) => result === 'PASS') &&
  exactGateSet(assessment.gates, E8_GATES, 'PASS') &&
  assessment.scorecard.baseVerifiedPoints === 100 &&
  assessment.scorecard.baseTotalPoints === 100 &&
  assessment.scorecard.highConfidenceBaseRubrics === 6 &&
  assessment.scorecard.signed === true &&
  assessment.quality.openP0 === 0 &&
  assessment.quality.openP1 === 0 &&
  assessment.quality.acceptedP2 === assessment.quality.openP2 &&
  assessment.quality.disqualifiers === 0 &&
  assessment.quality.openCriticalRisks === 0 &&
  assessment.demo.rehearsal === 'PASS' &&
  assessment.demo.contingency === 'READY' &&
  assessment.package.complete === true &&
  assessment.package.artifacts === 16 &&
  assessment.package.evidence === 48 &&
  assessment.package.cases === 32 &&
  assessment.package.auditControls === 72 &&
  assessment.decision === 'ACCEPTED' &&
  assessment.signatures.some(({ role }) => role === 'ACCEPTANCE_LEAD') &&
  assessment.handoffReady === true &&
  validUtc(assessment.generatedAtUtc);

const rejectedAssessment = (assessment) =>
  ['REJECTED', 'RETURN_TO_STAGE'].includes(assessment.decision) ||
  Object.values(assessment.gates).includes('FAIL') ||
  assessment.artifacts.some(({ status }) => ['FAILED', 'REJECTED'].includes(status)) ||
  assessment.evidence.some(({ status }) => ['FAILED', 'DISQUALIFIER'].includes(status)) ||
  assessment.cases.some(({ result }) => result === 'FAIL') ||
  assessment.auditControls.some(({ result }) => result === 'FAIL') ||
  assessment.quality.openP0 > 0 ||
  assessment.quality.openP1 > 0 ||
  assessment.quality.disqualifiers > 0 ||
  assessment.demo.rehearsal === 'FAIL';

const blockersFromAssessment = (assessment) => {
  const blockers = [];
  if (Object.values(assessment.gates).includes('BLOCKED_EXTERNAL'))
    blockers.push('BLOCKED_EXTERNAL_GATE');
  if (assessment.artifacts.some(({ status }) => status === 'BLOCKED_EXTERNAL'))
    blockers.push('BLOCKED_EXTERNAL_ARTIFACT');
  if (assessment.evidence.some(({ status }) => status === 'BLOCKED_EXTERNAL'))
    blockers.push('BLOCKED_EXTERNAL_EVIDENCE');
  if (assessment.cases.some(({ result }) => result === 'BLOCKED_EXTERNAL'))
    blockers.push('BLOCKED_EXTERNAL_CASE');
  if (assessment.auditControls.some(({ result }) => result === 'BLOCKED_EXTERNAL'))
    blockers.push('BLOCKED_EXTERNAL_AUDIT');
  if (assessment.auditControls.some(({ result }) => result === 'REVIEW_REQUIRED'))
    blockers.push('REVIEW_REQUIRED');
  return [...new Set(blockers)].sort();
};

const makeSnapshot = (body) => deepFreeze({ ...body, snapshotSha256: objectSha256(body) });

const validStage8Release = (value) =>
  exactKeys(value, ['releaseId', 'runtimeSha', 'submissionSha', 'tag', 'documentationCommit']) &&
  RELEASE_ID.test(value.releaseId ?? '') &&
  SHA.test(value.runtimeSha ?? '') &&
  SHA.test(value.submissionSha ?? '') &&
  validDocumentationCommit(value.documentationCommit, value.runtimeSha, value.submissionSha) &&
  RELEASE_TAG.test(value.tag ?? '');

const validStage8Scorecard = (value) =>
  exactKeys(value, [
    'baseVerifiedPoints',
    'baseTotalPoints',
    'bonusVerifiedPoints',
    'bonusTotalPoints',
    'highConfidenceBaseRubrics',
    'signed',
  ]) &&
  Number.isInteger(value.baseVerifiedPoints) &&
  value.baseVerifiedPoints >= 0 &&
  value.baseVerifiedPoints <= 100 &&
  value.baseTotalPoints === 100 &&
  Number.isInteger(value.bonusVerifiedPoints) &&
  value.bonusVerifiedPoints >= 0 &&
  value.bonusVerifiedPoints <= 50 &&
  value.bonusTotalPoints === 50 &&
  Number.isInteger(value.highConfidenceBaseRubrics) &&
  value.highConfidenceBaseRubrics >= 0 &&
  value.highConfidenceBaseRubrics <= 6 &&
  typeof value.signed === 'boolean';

const validStage8Quality = (value) =>
  exactKeys(value, [
    'openP0',
    'openP1',
    'openP2',
    'acceptedP2',
    'disqualifiers',
    'openCriticalRisks',
  ]) &&
  Object.values(value).every((count) => Number.isInteger(count) && count >= 0) &&
  value.acceptedP2 <= value.openP2;

export const validateStage8State = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'state',
      'blockers',
      'acceptanceId',
      'release',
      'urls',
      'gates',
      'scorecard',
      'quality',
      'assessmentSha256',
      'evidenceAuthoritySha256',
      'evidenceInventorySha256',
      'artifactBindingsSha256',
      'artifactInventorySha256',
      'handoffSha256',
      'finalizationAuthoritySha256',
      'catalogSha256',
      'decision',
      'containsSensitiveData',
      'snapshotSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 8 ||
    value.kind !== 'STAGE8_ACCEPTANCE_STATE' ||
    !['NOT_READY', 'IN_PROGRESS', 'READY_FOR_FINALIZATION', 'ACCEPTED', 'REJECTED'].includes(
      value.state,
    ) ||
    !Array.isArray(value.blockers) ||
    value.blockers.some(
      (blocker) =>
        !exactKeys(blocker, ['id', 'reason']) ||
        typeof blocker.id !== 'string' ||
        blocker.id.length === 0 ||
        typeof blocker.reason !== 'string' ||
        blocker.reason.length === 0,
    ) ||
    !validStage8GateStatuses(value.gates) ||
    value.catalogSha256 !== STAGE8_CATALOG_SHA256 ||
    !['PENDING', 'ACCEPTED', 'REJECTED', 'RETURN_TO_STAGE', 'REVIEW_REQUIRED'].includes(
      value.decision,
    ) ||
    value.containsSensitiveData !== false ||
    !SHA256.test(value.snapshotSha256 ?? '')
  ) {
    fail('E8_STATE_INVALID');
  }
  const body = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== 'snapshotSha256'),
  );
  if (value.snapshotSha256 !== objectSha256(body)) fail('E8_STATE_SHA256_INVALID');
  if (value.state === 'NOT_READY') {
    if (
      value.blockers.length !== 1 ||
      value.blockers[0].id !== 'BLK-E8-01' ||
      value.acceptanceId !== null ||
      value.release !== null ||
      value.urls !== null ||
      !exactGateSet(value.gates, E8_GATES, 'NOT_EVALUATED') ||
      value.scorecard !== null ||
      value.quality !== null ||
      value.assessmentSha256 !== null ||
      value.evidenceAuthoritySha256 !== null ||
      value.evidenceInventorySha256 !== null ||
      value.artifactBindingsSha256 !== null ||
      value.artifactInventorySha256 !== null ||
      value.handoffSha256 !== null ||
      value.finalizationAuthoritySha256 !== null ||
      value.decision !== 'PENDING'
    ) {
      fail('E8_STATE_NOT_READY_INVALID');
    }
    return value;
  }
  if (
    !ACCEPTANCE_ID.test(value.acceptanceId ?? '') ||
    !validStage8Release(value.release) ||
    !validUrls(value.urls) ||
    !validStage8Scorecard(value.scorecard) ||
    !validStage8Quality(value.quality) ||
    !SHA256.test(value.assessmentSha256 ?? '') ||
    value.blockers.some(({ id }) => id === 'BLK-E8-01')
  ) {
    fail('E8_STATE_EVALUATION_INVALID');
  }
  if (
    ['READY_FOR_FINALIZATION', 'ACCEPTED'].includes(value.state) &&
    (value.blockers.length !== 0 ||
      (value.state === 'READY_FOR_FINALIZATION'
        ? value.decision !== 'REVIEW_REQUIRED'
        : value.decision !== 'ACCEPTED') ||
      !(value.state === 'READY_FOR_FINALIZATION'
        ? finalizationReadyGates(value.gates)
        : exactGateSet(value.gates, E8_GATES, 'PASS')) ||
      value.scorecard.baseVerifiedPoints !== 100 ||
      value.scorecard.highConfidenceBaseRubrics !== 6 ||
      value.scorecard.signed !== true ||
      value.quality.openP0 !== 0 ||
      value.quality.openP1 !== 0 ||
      value.quality.acceptedP2 !== value.quality.openP2 ||
      value.quality.disqualifiers !== 0 ||
      value.quality.openCriticalRisks !== 0 ||
      !SHA256.test(value.evidenceAuthoritySha256 ?? '') ||
      !SHA256.test(value.evidenceInventorySha256 ?? '') ||
      value.artifactBindingsSha256 !== STAGE8_ARTIFACT_BINDINGS_SHA256)
  ) {
    fail('E8_STATE_FINALIZATION_READY_INVALID');
  }
  if (
    value.state === 'ACCEPTED' &&
    (!SHA256.test(value.artifactInventorySha256 ?? '') ||
      !SHA256.test(value.handoffSha256 ?? '') ||
      !SHA256.test(value.finalizationAuthoritySha256 ?? ''))
  ) {
    fail('E8_STATE_ACCEPTED_INVALID');
  }
  if (
    value.state === 'READY_FOR_FINALIZATION' &&
    (value.artifactInventorySha256 !== null ||
      value.handoffSha256 !== null ||
      value.finalizationAuthoritySha256 !== null)
  ) {
    fail('E8_STATE_FINALIZATION_BINDING_INVALID');
  }
  if (
    !['READY_FOR_FINALIZATION', 'ACCEPTED'].includes(value.state) &&
    [
      value.evidenceAuthoritySha256,
      value.evidenceInventorySha256,
      value.artifactBindingsSha256,
      value.artifactInventorySha256,
      value.handoffSha256,
      value.finalizationAuthoritySha256,
    ].some((binding) => binding !== null)
  ) {
    fail('E8_STATE_AUTHORITY_INVALID');
  }
  return value;
};

export const createStage8NotReady = (reason = 'E8_E7_INTAKE_MISSING') => {
  const snapshot = makeSnapshot({
    schemaVersion: 1,
    stage: 8,
    kind: 'STAGE8_ACCEPTANCE_STATE',
    state: 'NOT_READY',
    blockers: [{ id: 'BLK-E8-01', reason }],
    acceptanceId: null,
    release: null,
    urls: null,
    gates: initialGates(),
    scorecard: null,
    quality: null,
    assessmentSha256: null,
    evidenceAuthoritySha256: null,
    evidenceInventorySha256: null,
    artifactBindingsSha256: null,
    artifactInventorySha256: null,
    handoffSha256: null,
    finalizationAuthoritySha256: null,
    catalogSha256: STAGE8_CATALOG_SHA256,
    decision: 'PENDING',
    containsSensitiveData: false,
  });
  validateStage8State(snapshot);
  return snapshot;
};

export const deriveStage8State = ({
  intake,
  assessment,
  assessmentSource,
  evidenceIndexSource,
  evidencePackageSource,
  evidenceAuthority,
  evidenceRoot,
}) => {
  let evaluated;
  try {
    validateStage8IntakeResult(intake);
    evaluated = assessment ?? createStage8AssessmentTemplate(intake);
    validateStage8Assessment(evaluated, intake);
  } catch (error) {
    if (error instanceof Stage8ContractError) return createStage8NotReady(error.code);
    throw error;
  }
  const acceptanceClaimed = acceptedAssessment(evaluated);
  let evidenceMaterial = null;
  if (acceptanceClaimed) {
    try {
      evidenceMaterial = validateStage8EvidenceMaterial({
        intake,
        assessment: evaluated,
        assessmentSource,
        evidenceIndexSource,
        evidencePackageSource,
        evidenceAuthority,
        evidenceRoot,
      });
    } catch (error) {
      if (error instanceof Stage8ContractError) return createStage8NotReady(error.code);
      throw error;
    }
  }
  const state = acceptanceClaimed
    ? 'READY_FOR_FINALIZATION'
    : rejectedAssessment(evaluated)
      ? 'REJECTED'
      : 'IN_PROGRESS';
  const blockers = blockersFromAssessment(evaluated).map((reason) => ({ id: reason, reason }));
  const snapshot = makeSnapshot({
    schemaVersion: 1,
    stage: 8,
    kind: 'STAGE8_ACCEPTANCE_STATE',
    state,
    blockers,
    acceptanceId: evaluated.acceptanceId,
    release: intake.release,
    urls: intake.urls,
    gates:
      state === 'READY_FOR_FINALIZATION'
        ? { ...evaluated.gates, 'GATE-E8-03': 'BLOCKED_EXTERNAL' }
        : evaluated.gates,
    scorecard: evaluated.scorecard,
    quality: evaluated.quality,
    assessmentSha256: evaluated.assessmentSha256,
    evidenceAuthoritySha256: evidenceMaterial?.evidenceAuthoritySha256 ?? null,
    evidenceInventorySha256: evidenceMaterial?.evidenceInventory.inventorySha256 ?? null,
    artifactBindingsSha256: evidenceMaterial === null ? null : STAGE8_ARTIFACT_BINDINGS_SHA256,
    artifactInventorySha256: null,
    handoffSha256: null,
    finalizationAuthoritySha256: null,
    catalogSha256: STAGE8_CATALOG_SHA256,
    decision: state === 'READY_FOR_FINALIZATION' ? 'REVIEW_REQUIRED' : evaluated.decision,
    containsSensitiveData: false,
  });
  validateStage8State(snapshot);
  return snapshot;
};

export const evaluateStage8 = ({
  files,
  trustAnchor,
  assessment,
  assessmentSource,
  evidenceIndexSource,
  evidencePackageSource,
  evidenceAuthority,
  evidenceRoot,
  documentationAuthoritySource,
} = {}) => {
  if (files === undefined || trustAnchor === undefined) return createStage8NotReady();
  let intake;
  try {
    intake = validateStage7AcceptanceIntake({
      files,
      trustAnchor,
      documentationAuthoritySource,
    });
  } catch (error) {
    if (error instanceof Stage8ContractError) return createStage8NotReady(error.code);
    throw error;
  }
  return deriveStage8State({
    intake,
    assessment,
    assessmentSource,
    evidenceIndexSource,
    evidencePackageSource,
    evidenceAuthority,
    evidenceRoot,
  });
};

export const renderStage8Report = (snapshot) => {
  validateStage8State(snapshot);
  const release = snapshot.release;
  const notReadyReason = snapshot.blockers[0]?.reason ?? 'E8_E7_INTAKE_MISSING';
  const lines = [
    '# Etapa 8 — Aceptación y evaluación final',
    '',
    `Estado derivado: **${snapshot.state}**.`,
    `Catálogo: \`sha256:${snapshot.catalogSha256}\`.`,
    '',
  ];
  for (const [index, heading] of STAGE8_REPORT_HEADINGS.entries()) {
    lines.push(`## ${index + 1}. ${heading}`, '');
    if (index === 0) {
      lines.push(
        snapshot.state === 'NOT_READY'
          ? notReadyReason.startsWith('E8_EVIDENCE_')
            ? 'La aceptación no puede declararse: falta material de evidencia autenticado o no coincide con su autoridad.'
            : 'La evaluación no inició. Falta un intake E7 íntegro y autorizado.'
          : `La evaluación permanece en estado ${snapshot.state}; este reporte no agrega resultados no observados.`,
      );
    } else if (index === 1) {
      lines.push(
        release === null
          ? `Bloqueo: BLK-E8-01 (${notReadyReason}).`
          : `Release: \`${release.releaseId}\`; runtime SHA: \`${release.runtimeSha}\`; submission SHA: \`${release.submissionSha}\`; tag: \`${release.tag}\`.`,
      );
    } else if (index >= 32 && index <= 34) {
      const gate = E8_GATES[index - 32];
      lines.push(`Estado de ${gate}: **${snapshot.gates[gate]}**.`);
    } else if (index === 35) {
      lines.push(`Decisión: **${snapshot.decision}**.`);
    } else if (index === 36) {
      lines.push(
        snapshot.state === 'ACCEPTED'
          ? 'Handoff sujeto al artefacto STAGE8_HANDOFF_TO_STAGE9 validado.'
          : snapshot.state === 'READY_FOR_FINALIZATION'
            ? 'La matriz está lista, pero la aceptación permanece bloqueada hasta materializar el draft de handoff y validar la autoridad final externa byte a byte.'
            : 'Etapa 9 permanece bloqueada hasta GATE-E8-03 PASS y decisión ACCEPTED.',
      );
    } else {
      lines.push(
        snapshot.state === 'NOT_READY'
          ? 'Estado: **NOT_STARTED** por BLK-E8-01.'
          : 'Estado: sujeto exclusivamente al assessment ejecutado y sus evidencias.',
      );
    }
    lines.push('');
  }
  return `${lines.join('\n').trim()}\n`;
};

const validateOperationHandoff = (operation) => {
  if (
    !exactKeys(operation, [
      'expiresAtUtc',
      'ownerAlias',
      'dashboardUrl',
      'alarmsStatus',
      'budget',
      'rollbackRunbook',
      'cleanupRunbook',
      'evidenceRetention',
      'pendingTransactions',
      'incident',
      'contacts',
      'closeWindow',
    ]) ||
    !validUtc(operation.expiresAtUtc) ||
    !ALIAS.test(operation.ownerAlias ?? '') ||
    !validHttpsUrl(operation.dashboardUrl) ||
    operation.alarmsStatus !== 'READY' ||
    !exactKeys(operation.budget, ['currency', 'amount', 'asOfUtc']) ||
    !/^[A-Z]{3}$/u.test(operation.budget.currency ?? '') ||
    typeof operation.budget.amount !== 'number' ||
    !Number.isFinite(operation.budget.amount) ||
    operation.budget.amount < 0 ||
    !validUtc(operation.budget.asOfUtc) ||
    !['rollbackRunbook', 'cleanupRunbook'].every(
      (key) =>
        exactKeys(operation[key], ['url', 'sha256']) &&
        validHttpsUrl(operation[key].url) &&
        SHA256.test(operation[key].sha256 ?? ''),
    ) ||
    !exactKeys(operation.evidenceRetention, ['policyId', 'expiresAtUtc']) ||
    typeof operation.evidenceRetention.policyId !== 'string' ||
    operation.evidenceRetention.policyId.length < 3 ||
    !validUtc(operation.evidenceRetention.expiresAtUtc) ||
    !exactKeys(operation.pendingTransactions, ['status', 'count']) ||
    operation.pendingTransactions.status !== 'INVENTORIED' ||
    !Number.isInteger(operation.pendingTransactions.count) ||
    operation.pendingTransactions.count < 0 ||
    !exactKeys(operation.incident, ['status', 'id']) ||
    !['NONE', 'OPEN'].includes(operation.incident.status) ||
    (operation.incident.status === 'NONE' && operation.incident.id !== null) ||
    (operation.incident.status === 'OPEN' &&
      (typeof operation.incident.id !== 'string' || operation.incident.id.length < 3)) ||
    !Array.isArray(operation.contacts) ||
    operation.contacts.length === 0 ||
    operation.contacts.some((alias) => !ALIAS.test(alias ?? '')) ||
    !exactKeys(operation.closeWindow, ['startsAtUtc', 'endsAtUtc']) ||
    !validUtc(operation.closeWindow.startsAtUtc) ||
    !validUtc(operation.closeWindow.endsAtUtc) ||
    Date.parse(operation.closeWindow.startsAtUtc) >= Date.parse(operation.closeWindow.endsAtUtc)
  ) {
    fail('E8_STAGE9_OPERATION_HANDOFF_INVALID');
  }
  return operation;
};

const artifactInventoryForFinalization = ({
  evidenceMaterial,
  assessmentSource,
  evidenceIndexSource,
  handoffDraftSource,
}) => {
  const byEvidenceId = new Map(
    evidenceMaterial.evidenceInventory.inventory.map((entry) => [entry.id, entry]),
  );
  const special = {
    ASSESSMENT: {
      path: 'stage8-finalization/assessment.json',
      rawSha256: rawSha256(assessmentSource),
      bytes: sourceBuffer(assessmentSource, 'E8_FINALIZATION_ASSESSMENT').length,
    },
    HANDOFF: {
      path: 'stage8-finalization/handoff-draft.json',
      rawSha256: rawSha256(handoffDraftSource),
      bytes: sourceBuffer(handoffDraftSource, 'E8_FINALIZATION_HANDOFF').length,
    },
    EVIDENCE_INDEX: {
      path: 'stage8-finalization/evidence-index.json',
      rawSha256: rawSha256(evidenceIndexSource),
      bytes: sourceBuffer(evidenceIndexSource, 'E8_FINALIZATION_INDEX').length,
    },
  };
  const inventory = STAGE8_ARTIFACT_EVIDENCE_BINDINGS.map((binding) => {
    const evidenceSources = binding.evidenceIds.map((id) => {
      const source = byEvidenceId.get(id);
      if (source === undefined) fail('E8_ARTIFACT_EVIDENCE_BINDING_INVALID');
      return { path: source.path, rawSha256: source.rawSha256, bytes: source.bytes };
    });
    const sources =
      binding.material === 'EVIDENCE_SET'
        ? evidenceSources
        : [...evidenceSources, special[binding.material]];
    if (
      sources.some((source) => source === undefined) ||
      new Set(sources.map(({ path: sourcePath }) => sourcePath)).size !== sources.length
    ) {
      fail('E8_ARTIFACT_SOURCE_SET_INVALID');
    }
    return {
      id: binding.id,
      material: binding.material,
      evidenceIds: binding.evidenceIds,
      sources,
    };
  });
  return deepFreeze({ inventory, inventorySha256: objectSha256(inventory) });
};

const validateFinalizationAuthority = ({
  source,
  snapshot,
  intake,
  evidenceMaterial,
  artifactInventory,
  assessmentSource,
  evidenceIndexSource,
  evidencePackageSource,
  reportSource,
  handoffDraft,
  handoffDraftSource,
}) => {
  assertNoObviousSensitiveMaterial(source, 'E8_FINALIZATION_AUTHORITY');
  const parsed = parseJson(source, 'E8_FINALIZATION_AUTHORITY');
  const value = parsed.value;
  const expectedSourceHashes = {
    assessmentRawSha256: rawSha256(assessmentSource),
    indexRawSha256: rawSha256(evidenceIndexSource),
    packageRawSha256: rawSha256(evidencePackageSource),
    reportRawSha256: rawSha256(reportSource),
    handoffRawSha256: rawSha256(handoffDraftSource),
  };
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'acceptanceId',
      'release',
      'provisionalSnapshotSha256',
      'sourceHashes',
      'assessmentSha256',
      'indexSha256',
      'packageSha256',
      'reportSha256',
      'handoffSha256',
      'evidenceInventorySha256',
      'artifactBindingsSha256',
      'artifactInventory',
      'artifactInventorySha256',
      'ownerAlias',
      'approvedByAlias',
      'approvedAtUtc',
      'reason',
      'containsSensitiveData',
      'authoritySha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 8 ||
    value.kind !== 'STAGE8_ACCEPTANCE_FINALIZATION_AUTHORITY' ||
    value.status !== 'APPROVED' ||
    value.acceptanceId !== snapshot.acceptanceId ||
    canonicalJson(value.release) !== canonicalJson(intake.release) ||
    value.provisionalSnapshotSha256 !== snapshot.snapshotSha256 ||
    canonicalJson(value.sourceHashes) !== canonicalJson(expectedSourceHashes) ||
    value.assessmentSha256 !== evidenceMaterial.assessment.assessmentSha256 ||
    value.indexSha256 !== evidenceMaterial.index.indexSha256 ||
    value.packageSha256 !== evidenceMaterial.package.packageSha256 ||
    value.reportSha256 !== rawSha256(reportSource) ||
    value.handoffSha256 !== handoffDraft.handoffSha256 ||
    value.evidenceInventorySha256 !== evidenceMaterial.evidenceInventory.inventorySha256 ||
    value.artifactBindingsSha256 !== STAGE8_ARTIFACT_BINDINGS_SHA256 ||
    canonicalJson(value.artifactInventory) !== canonicalJson(artifactInventory.inventory) ||
    value.artifactInventorySha256 !== artifactInventory.inventorySha256 ||
    !ALIAS.test(value.ownerAlias ?? '') ||
    !ALIAS.test(value.approvedByAlias ?? '') ||
    value.ownerAlias === value.approvedByAlias ||
    !validUtc(value.approvedAtUtc) ||
    Date.parse(value.approvedAtUtc) < Date.parse(handoffDraft.generatedAtUtc) ||
    !validDocumentationReason(value.reason) ||
    value.containsSensitiveData !== false
  ) {
    fail('E8_FINALIZATION_AUTHORITY_INVALID');
  }
  const body = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== 'authoritySha256'),
  );
  if (value.authoritySha256 !== objectSha256(body)) {
    fail('E8_FINALIZATION_AUTHORITY_SHA256_INVALID');
  }
  return deepFreeze({ ...value, authorityRawSha256: rawSha256(parsed.buffer) });
};

export const createStage8HandoffDraft = ({
  snapshot,
  intake,
  assessmentSource,
  evidenceIndexSource,
  evidencePackageSource,
  evidenceAuthority,
  evidenceRoot,
  generatedAtUtc,
  report,
  reportSource,
  delivery,
  acceptance,
  operation,
}) => {
  validateStage8State(snapshot);
  const parsedAssessment = parseJson(assessmentSource, 'E8_STAGE9_ASSESSMENT');
  const evidenceMaterial = validateStage8EvidenceMaterial({
    intake,
    assessment: parsedAssessment.value,
    assessmentSource,
    evidenceIndexSource,
    evidencePackageSource,
    evidenceAuthority,
    evidenceRoot,
  });
  const reportBytes = sourceBuffer(reportSource, 'E8_STAGE9_REPORT');
  assertNoObviousSensitiveMaterial(reportBytes, 'E8_STAGE9_REPORT');
  if (
    snapshot.state !== 'READY_FOR_FINALIZATION' ||
    snapshot.decision !== 'REVIEW_REQUIRED' ||
    !finalizationReadyGates(snapshot.gates) ||
    snapshot.assessmentSha256 !== evidenceMaterial.assessment.assessmentSha256 ||
    snapshot.evidenceAuthoritySha256 !== evidenceMaterial.evidenceAuthoritySha256 ||
    snapshot.evidenceInventorySha256 !== evidenceMaterial.evidenceInventory.inventorySha256 ||
    snapshot.artifactBindingsSha256 !== STAGE8_ARTIFACT_BINDINGS_SHA256 ||
    canonicalJson(snapshot.release) !== canonicalJson(intake.release) ||
    canonicalJson(snapshot.urls) !== canonicalJson(intake.urls) ||
    !validUtc(generatedAtUtc) ||
    !exactKeys(report, ['filename', 'rawSha256']) ||
    report.filename !== REPORT_FILENAME ||
    !SHA256.test(report.rawSha256 ?? '') ||
    report.rawSha256 !== rawSha256(reportBytes) ||
    !exactKeys(delivery, ['repositoryPublic', 'readmeFinal']) ||
    delivery.repositoryPublic !== true ||
    delivery.readmeFinal !== true ||
    !exactKeys(acceptance, ['defectsAccepted', 'risksAccepted', 'deviationsAccepted']) ||
    acceptance.defectsAccepted !== true ||
    acceptance.risksAccepted !== true ||
    acceptance.deviationsAccepted !== true
  ) {
    fail('E8_STAGE9_HANDOFF_PRECONDITION_INVALID');
  }
  validateOperationHandoff(operation);
  const body = {
    schemaVersion: 1,
    schemaId: 'async-checkout-stage8-acceptance-handoff',
    stage: 8,
    kind: 'STAGE8_HANDOFF_TO_STAGE9',
    status: 'PENDING_FINAL_AUTHORITY',
    acceptanceId: snapshot.acceptanceId,
    generatedAtUtc,
    decision: 'ACCEPTED_PENDING_FINAL_AUTHORITY',
    release: snapshot.release,
    gates: snapshot.gates,
    urls: snapshot.urls,
    report,
    package: evidenceMaterial.packageEvidence,
    scorecard: {
      baseVerifiedPoints: snapshot.scorecard.baseVerifiedPoints,
      baseTotalPoints: snapshot.scorecard.baseTotalPoints,
      bonusVerifiedPoints: snapshot.scorecard.bonusVerifiedPoints,
      bonusTotalPoints: snapshot.scorecard.bonusTotalPoints,
      highConfidenceBaseRubrics: snapshot.scorecard.highConfidenceBaseRubrics,
    },
    quality: snapshot.quality,
    delivery,
    acceptance,
    operation,
    containsSensitiveData: false,
  };
  return deepFreeze({ ...body, handoffSha256: objectSha256(body) });
};

export const finalizeStage8Acceptance = (input) => {
  const draft = createStage8HandoffDraft(input);
  const draftSource = jsonBytes(draft);
  const evidenceMaterial = validateStage8EvidenceMaterial({
    intake: input.intake,
    assessment: parseJson(input.assessmentSource, 'E8_FINALIZATION_ASSESSMENT').value,
    assessmentSource: input.assessmentSource,
    evidenceIndexSource: input.evidenceIndexSource,
    evidencePackageSource: input.evidencePackageSource,
    evidenceAuthority: input.evidenceAuthority,
    evidenceRoot: input.evidenceRoot,
  });
  const artifactInventory = artifactInventoryForFinalization({
    evidenceMaterial,
    assessmentSource: input.assessmentSource,
    evidenceIndexSource: input.evidenceIndexSource,
    handoffDraftSource: draftSource,
  });
  const authority = validateFinalizationAuthority({
    source: input.finalizationAuthoritySource,
    snapshot: input.snapshot,
    intake: input.intake,
    evidenceMaterial,
    artifactInventory,
    assessmentSource: input.assessmentSource,
    evidenceIndexSource: input.evidenceIndexSource,
    evidencePackageSource: input.evidencePackageSource,
    reportSource: input.reportSource,
    handoffDraft: draft,
    handoffDraftSource: draftSource,
  });
  const draftBody = Object.fromEntries(
    Object.entries(draft).filter(([key]) => key !== 'handoffSha256'),
  );
  const finalBody = {
    ...draftBody,
    status: 'READY_FOR_STAGE9',
    decision: 'ACCEPTED',
    gates: Object.fromEntries(E8_GATES.map((gate) => [gate, 'PASS'])),
    finalization: {
      draftRawSha256: rawSha256(draftSource),
      draftSha256: draft.handoffSha256,
      authority,
    },
  };
  const handoff = deepFreeze({ ...finalBody, handoffSha256: objectSha256(finalBody) });
  const snapshotBody = {
    ...Object.fromEntries(
      Object.entries(input.snapshot).filter(([key]) => key !== 'snapshotSha256'),
    ),
    state: 'ACCEPTED',
    decision: 'ACCEPTED',
    gates: handoff.gates,
    artifactInventorySha256: artifactInventory.inventorySha256,
    handoffSha256: handoff.handoffSha256,
    finalizationAuthoritySha256: authority.authoritySha256,
  };
  const snapshot = makeSnapshot(snapshotBody);
  validateStage8State(snapshot);
  return deepFreeze({ snapshot, handoff, finalizationAuthority: authority });
};

export const createStage8Handoff = (input) => finalizeStage8Acceptance(input).handoff;

const jsonBytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
const digest = (character) => character.repeat(64);

const buildStage7Fixture = ({
  candidate = 'a'.repeat(40),
  submission = candidate,
  releaseSuffix = 'abcdef0',
  changedPaths = ['README.md'],
} = {}) => {
  const releaseId = `rel-20260818-0101-${releaseSuffix}`;
  const releaseTag = 'v1.0.0';
  const generatedAtUtc = '2026-08-18T06:00:00.000Z';
  const ownerAlias = 'release-owner';
  const application = 'https://checkout.example.invalid';
  const urls = {
    application,
    api: `${application}/api`,
    docs: `${application}/api/docs`,
    health: `${application}/api/health/ready`,
    repository: 'https://github.com/ivanmonsalve0404/async-checkout-demo',
  };
  const source = {
    path: 'output/evidence/runtime/stage-7/stage7-source-fixture/source.json',
    sha256: digest('1'),
    artifactName: 'stage7-source-fixture',
    producerJob: 'summary',
    selectors: ['$.fixture'],
  };
  const handoff = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_HANDOFF_TO_STAGE8',
    status: 'READY_FOR_STAGE8',
    scope: 'full',
    candidateSha: candidate,
    releaseId,
    releaseTag,
    ownerAlias,
    generatedAtUtc,
    itemCount: 37,
    readyCount: 37,
    items: Array.from({ length: 37 }, (_, index) => ({
      number: index + 1,
      label: `Handoff item ${index + 1}`,
      status: 'READY',
      dependencyIds: ['EVD-E7-01'],
      sources: [source],
    })),
    nextStage: 8,
    containsSensitiveData: false,
  };
  const handoffBytes = jsonBytes(handoff);
  const ledgerBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_PROVENANCE_LEDGER',
    status: 'VERIFIED',
    scope: 'full',
    candidateSha: candidate,
    releaseId,
    releaseTag,
    generatedAtUtc,
    ownerAlias,
    entryGate: 'PASS',
    catalogSha256: objectSha256({
      artifacts: STAGE7_SOURCE_ARTIFACTS,
      evidence: STAGE7_SOURCE_EVIDENCE,
    }),
    counts: { artifacts: { verified: 20, total: 20 }, evidence: { pass: 57, total: 57 } },
    gates: Object.fromEntries(E7_GATES.map((gate) => [gate, 'PASS'])),
    artifacts: Array.from({ length: 20 }, (_, index) => ({
      id: `ART-REL-${String(index + 1).padStart(2, '0')}`,
      name: STAGE7_SOURCE_ARTIFACTS[index].name,
      status: 'VERIFIED',
      ownerAlias,
      validatedAtUtc: generatedAtUtc,
      validator: 'fixtureValidator',
      sources: [source],
    })),
    evidence: Array.from({ length: 57 }, (_, index) => ({
      id: `EVD-E7-${String(index + 1).padStart(2, '0')}`,
      name: STAGE7_SOURCE_EVIDENCE[index].name,
      status: 'PASS',
      ownerAlias,
      validatedAtUtc: generatedAtUtc,
      validator: 'fixtureValidator',
      sources: [source],
    })),
    sourceBindings: Object.fromEntries(
      STAGE7_LEDGER_SOURCE_BINDING_SPECS.map(({ key, basename }, index) => [
        key,
        {
          status: 'BOUND',
          basename,
          path: `output/evidence/runtime/stage-7/stage7-source-fixture/${basename}`,
          artifactName: 'stage7-source-fixture',
          producerJob: 'summary',
          rawSha256: digest(String((index + 1) % 10)),
          objectSha256: digest(String((index + 2) % 10)),
        },
      ]),
    ),
    handoffContentSha256: objectSha256(handoff),
    nextStage: 8,
    containsSensitiveData: false,
  };
  const ledger = { ...ledgerBody, ledgerSha256: objectSha256(ledgerBody) };
  const ledgerBytes = jsonBytes(ledger);
  const reportLines = [
    '# Etapa 7 — Release y despliegue (reporte ejecutado)',
    '',
    `- Candidato: \`${candidate}\``,
    `- Release: \`${releaseId}\` / \`${releaseTag}\``,
    '- Estado de cierre: **VERIFIED**',
    '',
  ];
  for (const [index, heading] of STAGE7_REPORT_HEADINGS.entries()) {
    reportLines.push(
      `## ${index + 1}. ${heading}`,
      '',
      'Estado: **PASS**.',
      `Evidencia causal verificada para ${releaseId}; fuente sanitizada y ligada por sha256.`,
      '',
    );
  }
  const report = `${reportLines.join('\n').trim()}\n`;
  const reportBytes = Buffer.from(report);
  const authority = (character) => digest(character);
  const manifestBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_FINAL_RELEASE_MANIFEST',
    status: 'RELEASED',
    scope: 'full',
    candidateSha: candidate,
    runtimeSha: candidate,
    submissionSha: submission,
    releaseId,
    releaseTag,
    generatedAtUtc,
    ownerAlias,
    releaseMode: 'VERSIONED_UPDATE',
    authorities: {
      stage6CloseoutSha256: authority('3'),
      jobResultsSha256: authority('4'),
      provenanceLedgerSha256: rawSha256(ledgerBytes),
      evidenceIndexSha256: authority('5'),
      gateEvaluationSha256: authority('6'),
      scorecardSha256: authority('7'),
      operationsRunbookSha256: authority('8'),
      handoffSha256: rawSha256(handoffBytes),
      executedReportSha256: rawSha256(reportBytes),
    },
    contentBindings: {
      stage6CloseoutSha256: authority('9'),
      jobResultsSha256: authority('a'),
      provenanceLedgerSha256: objectSha256(ledger),
      evidenceIndexSha256: authority('b'),
      gateEvaluationSha256: authority('c'),
      scorecardSha256: authority('d'),
      operationsRunbookSha256: authority('e'),
      handoffSha256: objectSha256(handoff),
    },
    artifacts: { verified: 20, total: 20 },
    evidence: { pass: 57, total: 57 },
    gates: Object.fromEntries(E7_GATES.map((gate) => [gate, 'PASS'])),
    publication: {
      releaseUrl: `${urls.repository}/releases/tag/${releaseTag}`,
      readmeCommitSha: submission,
      repositoryPublic: true,
      urlsVerified: true,
      proofRawSha256: authority('f'),
      proofObjectSha256: authority('0'),
    },
    rollback: {
      predecessorManifestSha256: authority('1'),
      completionRawSha256: authority('2'),
      completionObjectSha256: authority('3'),
      completionEnvelopeSha256: authority('4'),
    },
    urls,
    nextStage: 8,
    containsSensitiveData: false,
  };
  const manifest = { ...manifestBody, manifestSha256: objectSha256(manifestBody) };
  const manifestBytes = jsonBytes(manifest);
  const closeoutIndex = createStage7Index({
    entryGate: 'PASS',
    artifactStates: Object.fromEntries(ledger.artifacts.map(({ id, status }) => [id, status])),
    evidenceStates: Object.fromEntries(
      ledger.evidence.slice(0, 54).map(({ id, status }) => [id, status]),
    ),
  });
  const closeout = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_CLOSEOUT',
    status: 'RELEASED',
    candidateSha: candidate,
    releaseId,
    releaseTag,
    stage6RunId: 'e6-20260818t010101z-abcdef01',
    stage6ManifestSha256: authority('5'),
    releaseMode: 'VERSIONED_UPDATE',
    updateReleaseSupported: true,
    updateReleaseUnsupportedReason: null,
    cloudFormationDrift: { checked: 4, criticalCount: 0, status: 'IN_SYNC' },
    authorizationLedger: { status: 'PASS' },
    publication: {
      releaseUrl: manifest.publication.releaseUrl,
      readmeCommitSha: submission,
      repositoryPublic: true,
      urlsVerified: true,
    },
    jobs: ['summary'],
    index: closeoutIndex,
    gates: manifest.gates,
    artifacts: manifest.artifacts,
    evidence: manifest.evidence,
    releaseManifestSha256: manifest.manifestSha256,
    provenanceLedgerSha256: ledger.ledgerSha256,
    nextStage: 8,
    mutationsPerformedByVerifier: 0,
    containsSensitiveData: false,
  };
  const closeoutBytes = jsonBytes(closeout);
  let documentationAuthoritySource;
  let documentationAuthorityRawSha256 = null;
  let documentationAuthoritySha256 = null;
  if (submission !== candidate) {
    const documentationAuthorityBody = {
      schemaVersion: 1,
      stage: 8,
      kind: 'STAGE8_DOCUMENTATION_COMMIT_AUTHORITY',
      status: 'APPROVED',
      fromSha: candidate,
      toSha: submission,
      changedPaths: [...changedPaths].toSorted(),
      ownerAlias,
      approvedByAlias: 'acceptance-lead',
      approvedAtUtc: '2026-08-18T06:30:00.000Z',
      reason: 'Commit posterior limitado a documentación y aprobado para evaluación final.',
      sourceHashes: {
        commitMetadataRawSha256: authority('6'),
        changedPathsRawSha256: authority('7'),
        approvalRawSha256: authority('8'),
        updatedManifestRawSha256: rawSha256(manifestBytes),
      },
      containsSensitiveData: false,
    };
    const documentationAuthority = {
      ...documentationAuthorityBody,
      authoritySha256: objectSha256(documentationAuthorityBody),
    };
    documentationAuthoritySource = jsonBytes(documentationAuthority);
    documentationAuthorityRawSha256 = rawSha256(documentationAuthoritySource);
    documentationAuthoritySha256 = documentationAuthority.authoritySha256;
  }
  const trustAnchor = {
    schemaVersion: 1,
    stage: 8,
    kind: 'STAGE8_E7_TRUST_ANCHOR',
    releaseManifestRawSha256: rawSha256(manifestBytes),
    closeoutRawSha256: rawSha256(closeoutBytes),
    releaseId,
    runtimeSha: candidate,
    submissionSha: submission,
    documentationAuthorityRawSha256,
    documentationAuthoritySha256,
    tag: releaseTag,
    urls,
    containsSensitiveData: false,
  };
  return {
    files: {
      report: reportBytes,
      manifest: manifestBytes,
      ledger: ledgerBytes,
      closeout: closeoutBytes,
      handoff: handoffBytes,
    },
    trustAnchor,
    documentationAuthoritySource,
  };
};

const rehashAssessment = (assessment) => {
  const body = Object.fromEntries(
    Object.entries(assessment).filter(([key]) => key !== 'assessmentSha256'),
  );
  return { ...body, assessmentSha256: objectSha256(body) };
};

const acceptedFixtureAssessment = (intake, evidenceRoot, { notApplicableIds = [] } = {}) => {
  const template = createStage8AssessmentTemplate(intake);
  mkdirSync(evidenceRoot, { recursive: true });
  const evidence = STAGE8_EVIDENCE.map(({ id }) => {
    const status = notApplicableIds.includes(id) ? 'NOT_APPLICABLE_APPROVED' : 'VERIFIED_FULL';
    const sourcePath = `${id.toLowerCase()}.json`;
    const capturedAtUtc = '2026-08-18T07:00:00.000Z';
    const ownerAlias = 'acceptance-lead';
    let document;
    if (status === 'NOT_APPLICABLE_APPROVED') {
      const body = {
        schemaVersion: 1,
        stage: 8,
        kind: 'STAGE8_NOT_APPLICABLE_APPROVAL',
        status: 'APPROVED',
        acceptanceId: template.acceptanceId,
        evidenceId: id,
        release: intake.release,
        ownerAlias,
        approvedByAlias: 'independent-observer',
        approvedAtUtc: capturedAtUtc,
        reason: 'Control no aplicable aprobado con evidencia causal independiente.',
        containsSensitiveData: false,
      };
      document = { ...body, approvalSha256: objectSha256(body) };
    } else {
      document = {
        schemaVersion: 1,
        stage: 8,
        kind: 'STAGE8_VERIFIED_EVIDENCE_FIXTURE',
        acceptanceId: template.acceptanceId,
        evidenceId: id,
        release: intake.release,
        observedAtUtc: capturedAtUtc,
        result: 'VERIFIED_FULL',
        containsSensitiveData: false,
      };
    }
    const bytes = jsonBytes(document);
    writeFileSync(path.join(evidenceRoot, sourcePath), bytes, { flag: 'wx' });
    return {
      id,
      status,
      sourcePath,
      rawSha256: rawSha256(bytes),
      capturedAtUtc,
      ownerAlias,
    };
  });
  return rehashAssessment({
    ...template,
    generatedAtUtc: '2026-08-18T07:00:00.000Z',
    artifacts: STAGE8_ARTIFACTS.map(({ id, acceptedState }) => ({ id, status: acceptedState })),
    evidence,
    cases: STAGE8_CASES.map(({ id }, index) => ({
      id,
      result: 'PASS',
      evidenceIds: [STAGE8_EVIDENCE[index].id],
    })),
    auditControls: STAGE8_AUDIT_CONTROLS.map(({ id }, index) => ({
      id,
      result: 'PASS',
      evidenceIds: [STAGE8_EVIDENCE[index % STAGE8_EVIDENCE.length].id],
    })),
    gates: Object.fromEntries(E8_GATES.map((gate) => [gate, 'PASS'])),
    scorecard: {
      baseVerifiedPoints: 100,
      baseTotalPoints: 100,
      bonusVerifiedPoints: 40,
      bonusTotalPoints: 50,
      highConfidenceBaseRubrics: 6,
      signed: true,
    },
    quality: {
      openP0: 0,
      openP1: 0,
      openP2: 1,
      acceptedP2: 1,
      disqualifiers: 0,
      openCriticalRisks: 0,
    },
    demo: { rehearsal: 'PASS', contingency: 'READY' },
    package: { complete: true, artifacts: 16, evidence: 48, cases: 32, auditControls: 72 },
    decision: 'ACCEPTED',
    signatures: [
      {
        role: 'ACCEPTANCE_LEAD',
        alias: 'acceptance-lead',
        signedAtUtc: '2026-08-18T07:00:00.000Z',
      },
    ],
    handoffReady: true,
  });
};

const buildStage8EvidenceMaterialFixture = (intake, assessment, evidenceRoot) => {
  const assessmentSource = jsonBytes(assessment);
  const evidenceInventory = readStage8EvidenceInventory({ evidenceRoot, assessment, intake });
  const indexBody = {
    schemaVersion: 1,
    stage: 8,
    kind: 'STAGE8_EVIDENCE_INDEX',
    acceptanceId: assessment.acceptanceId,
    release: intake.release,
    generatedAtUtc: assessment.generatedAtUtc,
    entries: assessment.evidence,
    evidenceInventory: evidenceInventory.inventory,
    evidenceInventorySha256: evidenceInventory.inventorySha256,
    artifactBindings: STAGE8_ARTIFACT_EVIDENCE_BINDINGS,
    artifactBindingsSha256: STAGE8_ARTIFACT_BINDINGS_SHA256,
    containsSensitiveData: false,
  };
  const index = { ...indexBody, indexSha256: objectSha256(indexBody) };
  const evidenceIndexSource = jsonBytes(index);
  const packageBody = {
    schemaVersion: 1,
    stage: 8,
    kind: 'STAGE8_EVIDENCE_PACKAGE',
    acceptanceId: assessment.acceptanceId,
    release: intake.release,
    generatedAtUtc: assessment.generatedAtUtc,
    assessmentRawSha256: rawSha256(assessmentSource),
    assessmentSha256: assessment.assessmentSha256,
    indexRawSha256: rawSha256(evidenceIndexSource),
    indexSha256: index.indexSha256,
    evidenceInventory: evidenceInventory.inventory,
    evidenceInventorySha256: evidenceInventory.inventorySha256,
    artifactBindings: STAGE8_ARTIFACT_EVIDENCE_BINDINGS,
    artifactBindingsSha256: STAGE8_ARTIFACT_BINDINGS_SHA256,
    counts: { artifacts: 16, evidence: 48, cases: 32, auditControls: 72 },
    containsSensitiveData: false,
  };
  const package_ = { ...packageBody, packageSha256: objectSha256(packageBody) };
  const evidencePackageSource = jsonBytes(package_);
  const evidenceAuthority = {
    schemaVersion: 1,
    stage: 8,
    kind: 'STAGE8_EVIDENCE_AUTHORITY',
    acceptanceId: assessment.acceptanceId,
    release: intake.release,
    assessmentRawSha256: rawSha256(assessmentSource),
    assessmentSha256: assessment.assessmentSha256,
    indexRawSha256: rawSha256(evidenceIndexSource),
    indexSha256: index.indexSha256,
    packageRawSha256: rawSha256(evidencePackageSource),
    packageSha256: package_.packageSha256,
    evidenceInventorySha256: evidenceInventory.inventorySha256,
    artifactBindingsSha256: STAGE8_ARTIFACT_BINDINGS_SHA256,
    issuerAlias: 'acceptance-authority',
    issuedAtUtc: '2026-08-18T07:05:00.000Z',
    containsSensitiveData: false,
  };
  return {
    assessmentSource,
    evidenceIndexSource,
    evidencePackageSource,
    evidenceAuthority,
    evidenceRoot,
  };
};

const buildFinalizationAuthorityFixture = (input) => {
  const draft = createStage8HandoffDraft(input);
  const draftSource = jsonBytes(draft);
  const evidenceMaterial = validateStage8EvidenceMaterial({
    intake: input.intake,
    assessment: parseJson(input.assessmentSource, 'E8_FIXTURE_ASSESSMENT').value,
    assessmentSource: input.assessmentSource,
    evidenceIndexSource: input.evidenceIndexSource,
    evidencePackageSource: input.evidencePackageSource,
    evidenceAuthority: input.evidenceAuthority,
    evidenceRoot: input.evidenceRoot,
  });
  const artifactInventory = artifactInventoryForFinalization({
    evidenceMaterial,
    assessmentSource: input.assessmentSource,
    evidenceIndexSource: input.evidenceIndexSource,
    handoffDraftSource: draftSource,
  });
  const body = {
    schemaVersion: 1,
    stage: 8,
    kind: 'STAGE8_ACCEPTANCE_FINALIZATION_AUTHORITY',
    status: 'APPROVED',
    acceptanceId: input.snapshot.acceptanceId,
    release: input.intake.release,
    provisionalSnapshotSha256: input.snapshot.snapshotSha256,
    sourceHashes: {
      assessmentRawSha256: rawSha256(input.assessmentSource),
      indexRawSha256: rawSha256(input.evidenceIndexSource),
      packageRawSha256: rawSha256(input.evidencePackageSource),
      reportRawSha256: rawSha256(input.reportSource),
      handoffRawSha256: rawSha256(draftSource),
    },
    assessmentSha256: evidenceMaterial.assessment.assessmentSha256,
    indexSha256: evidenceMaterial.index.indexSha256,
    packageSha256: evidenceMaterial.package.packageSha256,
    reportSha256: rawSha256(input.reportSource),
    handoffSha256: draft.handoffSha256,
    evidenceInventorySha256: evidenceMaterial.evidenceInventory.inventorySha256,
    artifactBindingsSha256: STAGE8_ARTIFACT_BINDINGS_SHA256,
    artifactInventory: artifactInventory.inventory,
    artifactInventorySha256: artifactInventory.inventorySha256,
    ownerAlias: 'acceptance-lead',
    approvedByAlias: 'independent-observer',
    approvedAtUtc: input.generatedAtUtc,
    reason: 'Finalización externa aprobada tras materializar y verificar el handoff completo.',
    containsSensitiveData: false,
  };
  return jsonBytes({ ...body, authoritySha256: objectSha256(body) });
};

export const selfTestStage8Contract = () => {
  assertCatalog();
  const temporaryRoot = mkdtempSync(path.join(os.tmpdir(), 'stage8-contract-selftest-'));
  try {
    const fixture = buildStage7Fixture();
    const intake = validateStage7AcceptanceIntake(fixture);
    assert.equal(intake.release.documentationCommit.mode, 'SAME_COMMIT');
    assert.equal(deriveStage8State({ intake }).state, 'IN_PROGRESS');
    assert.equal(evaluateStage8().state, 'NOT_READY');

    const documentaryFixture = buildStage7Fixture({
      submission: 'b'.repeat(40),
      releaseSuffix: '1234567',
    });
    const documentaryIntake = validateStage7AcceptanceIntake(documentaryFixture);
    assert.equal(documentaryIntake.release.runtimeSha, 'a'.repeat(40));
    assert.equal(documentaryIntake.release.submissionSha, 'b'.repeat(40));
    assert.equal(documentaryIntake.release.documentationCommit.mode, 'DOCUMENTATION_ONLY_APPROVED');
    const missingDocumentaryAuthority = evaluateStage8({
      files: documentaryFixture.files,
      trustAnchor: documentaryFixture.trustAnchor,
    });
    assert.equal(missingDocumentaryAuthority.state, 'NOT_READY');
    assert.equal(
      missingDocumentaryAuthority.blockers[0].reason,
      'E8_DOCUMENTATION_AUTHORITY_MISSING',
    );
    const functionalChange = buildStage7Fixture({
      submission: 'c'.repeat(40),
      releaseSuffix: '2345678',
      changedPaths: ['apps/api/src/main.ts'],
    });
    assert.equal(evaluateStage8(functionalChange).state, 'NOT_READY');
    const tamperedDocumentaryAuthority = {
      ...documentaryFixture,
      documentationAuthoritySource: Buffer.concat([
        documentaryFixture.documentationAuthoritySource,
        Buffer.from('\n'),
      ]),
    };
    assert.equal(evaluateStage8(tamperedDocumentaryAuthority).state, 'NOT_READY');

    const missingStage7 = { ...fixture.files };
    delete missingStage7.report;
    assert.equal(
      evaluateStage8({ files: missingStage7, trustAnchor: fixture.trustAnchor }).state,
      'NOT_READY',
    );
    const foreign = buildStage7Fixture({ candidate: 'd'.repeat(40), releaseSuffix: '3456789' });
    assert.equal(
      evaluateStage8({
        files: { ...fixture.files, handoff: foreign.files.handoff },
        trustAnchor: fixture.trustAnchor,
      }).state,
      'NOT_READY',
    );

    const buildMaterial = (name, options) => {
      const evidenceRoot = path.join(temporaryRoot, name);
      const assessment = acceptedFixtureAssessment(intake, evidenceRoot, options);
      const material = buildStage8EvidenceMaterialFixture(intake, assessment, evidenceRoot);
      return { evidenceRoot, assessment, material };
    };
    const acceptedFixture = buildMaterial('accepted');
    const missingEvidenceAuthority = deriveStage8State({
      intake,
      assessment: acceptedFixture.assessment,
      evidenceRoot: acceptedFixture.evidenceRoot,
    });
    assert.equal(missingEvidenceAuthority.state, 'NOT_READY');
    const ready = deriveStage8State({
      intake,
      assessment: acceptedFixture.assessment,
      ...acceptedFixture.material,
    });
    assert.equal(ready.state, 'READY_FOR_FINALIZATION');
    assert.equal(ready.decision, 'REVIEW_REQUIRED');
    assert.equal(ready.gates['GATE-E8-03'], 'BLOCKED_EXTERNAL');
    assert.notEqual(ready.state, 'ACCEPTED');

    const noRoot = deriveStage8State({
      intake,
      assessment: acceptedFixture.assessment,
      ...acceptedFixture.material,
      evidenceRoot: undefined,
    });
    assert.equal(noRoot.state, 'NOT_READY');
    assert.equal(noRoot.blockers[0].reason, 'E8_EVIDENCE_AUTHORITY_MISSING');

    const missingFile = buildMaterial('missing-file');
    rmSync(path.join(missingFile.evidenceRoot, 'evd-e8-01.json'));
    assert.equal(
      deriveStage8State({ intake, assessment: missingFile.assessment, ...missingFile.material })
        .state,
      'NOT_READY',
    );
    const tamperedFile = buildMaterial('tampered-file');
    writeFileSync(
      path.join(tamperedFile.evidenceRoot, 'evd-e8-01.json'),
      Buffer.from('{"tampered":true}\n'),
    );
    assert.equal(
      deriveStage8State({ intake, assessment: tamperedFile.assessment, ...tamperedFile.material })
        .state,
      'NOT_READY',
    );
    const swappedFiles = buildMaterial('swapped-files');
    const first = readFileSync(path.join(swappedFiles.evidenceRoot, 'evd-e8-01.json'));
    const second = readFileSync(path.join(swappedFiles.evidenceRoot, 'evd-e8-02.json'));
    writeFileSync(path.join(swappedFiles.evidenceRoot, 'evd-e8-01.json'), second);
    writeFileSync(path.join(swappedFiles.evidenceRoot, 'evd-e8-02.json'), first);
    assert.equal(
      deriveStage8State({ intake, assessment: swappedFiles.assessment, ...swappedFiles.material })
        .state,
      'NOT_READY',
    );
    const extraFile = buildMaterial('extra-file');
    writeFileSync(path.join(extraFile.evidenceRoot, 'extra.json'), Buffer.from('{}\n'));
    assert.equal(
      deriveStage8State({ intake, assessment: extraFile.assessment, ...extraFile.material }).state,
      'NOT_READY',
    );
    const traversalAssessment = rehashAssessment({
      ...acceptedFixture.assessment,
      evidence: acceptedFixture.assessment.evidence.map((row, index) =>
        index === 0 ? { ...row, sourcePath: '../escape.json' } : row,
      ),
    });
    assert.equal(
      deriveStage8State({
        intake,
        assessment: traversalAssessment,
        ...acceptedFixture.material,
      }).state,
      'NOT_READY',
    );
    const duplicatePathAssessment = rehashAssessment({
      ...acceptedFixture.assessment,
      evidence: acceptedFixture.assessment.evidence.map((row, index) =>
        index === 1 ? { ...row, sourcePath: 'evd-e8-01.json' } : row,
      ),
    });
    assert.equal(
      deriveStage8State({
        intake,
        assessment: duplicatePathAssessment,
        ...acceptedFixture.material,
      }).state,
      'NOT_READY',
    );

    const approvedNotApplicable = buildMaterial('not-applicable', {
      notApplicableIds: ['EVD-E8-48'],
    });
    assert.equal(
      deriveStage8State({
        intake,
        assessment: approvedNotApplicable.assessment,
        ...approvedNotApplicable.material,
      }).state,
      'READY_FOR_FINALIZATION',
    );
    const invalidApprovalBytes = jsonBytes({ status: 'APPROVED' });
    writeFileSync(
      path.join(approvedNotApplicable.evidenceRoot, 'evd-e8-48.json'),
      invalidApprovalBytes,
    );
    const invalidApprovalAssessment = rehashAssessment({
      ...approvedNotApplicable.assessment,
      evidence: approvedNotApplicable.assessment.evidence.map((row) =>
        row.id === 'EVD-E8-48' ? { ...row, rawSha256: rawSha256(invalidApprovalBytes) } : row,
      ),
    });
    assert.equal(
      deriveStage8State({
        intake,
        assessment: invalidApprovalAssessment,
        ...approvedNotApplicable.material,
      }).state,
      'NOT_READY',
    );

    const artifactSwapPackage = parseStrictJsonSource(
      acceptedFixture.material.evidencePackageSource,
      { scanForbiddenData: false },
    );
    artifactSwapPackage.artifactBindings = [...artifactSwapPackage.artifactBindings].reverse();
    const artifactSwapBody = Object.fromEntries(
      Object.entries(artifactSwapPackage).filter(([key]) => key !== 'packageSha256'),
    );
    artifactSwapPackage.packageSha256 = objectSha256(artifactSwapBody);
    assert.equal(
      deriveStage8State({
        intake,
        assessment: acceptedFixture.assessment,
        ...acceptedFixture.material,
        evidencePackageSource: jsonBytes(artifactSwapPackage),
      }).state,
      'NOT_READY',
    );
    const artifactDuplicatePackage = parseStrictJsonSource(jsonBytes(artifactSwapPackage), {
      scanForbiddenData: false,
    });
    artifactDuplicatePackage.artifactBindings = [
      ...STAGE8_ARTIFACT_EVIDENCE_BINDINGS,
      STAGE8_ARTIFACT_EVIDENCE_BINDINGS[0],
    ];
    const duplicateBody = Object.fromEntries(
      Object.entries(artifactDuplicatePackage).filter(([key]) => key !== 'packageSha256'),
    );
    artifactDuplicatePackage.packageSha256 = objectSha256(duplicateBody);
    assert.equal(
      deriveStage8State({
        intake,
        assessment: acceptedFixture.assessment,
        ...acceptedFixture.material,
        evidencePackageSource: jsonBytes(artifactDuplicatePackage),
      }).state,
      'NOT_READY',
    );

    const reportSource = Buffer.from('# Etapa 8 — Aceptación final ejecutada\n');
    const handoffInput = {
      snapshot: ready,
      intake,
      ...acceptedFixture.material,
      generatedAtUtc: '2026-08-18T08:00:00.000Z',
      report: { filename: REPORT_FILENAME, rawSha256: rawSha256(reportSource) },
      reportSource,
      delivery: { repositoryPublic: true, readmeFinal: true },
      acceptance: { defectsAccepted: true, risksAccepted: true, deviationsAccepted: true },
      operation: {
        expiresAtUtc: '2026-09-01T00:00:00.000Z',
        ownerAlias: 'operations-owner',
        dashboardUrl: 'https://console.example.invalid/dashboard',
        alarmsStatus: 'READY',
        budget: { currency: 'USD', amount: 25, asOfUtc: '2026-08-18T08:00:00.000Z' },
        rollbackRunbook: { url: 'https://docs.example.invalid/rollback', sha256: digest('4') },
        cleanupRunbook: { url: 'https://docs.example.invalid/cleanup', sha256: digest('5') },
        evidenceRetention: {
          policyId: 'retention-30-days',
          expiresAtUtc: '2026-09-17T08:00:00.000Z',
        },
        pendingTransactions: { status: 'INVENTORIED', count: 0 },
        incident: { status: 'NONE', id: null },
        contacts: ['operations-owner'],
        closeWindow: {
          startsAtUtc: '2026-08-18T08:00:00.000Z',
          endsAtUtc: '2026-08-25T08:00:00.000Z',
        },
      },
    };
    const draft = createStage8HandoffDraft(handoffInput);
    assert.equal(draft.status, 'PENDING_FINAL_AUTHORITY');
    assert.throws(() => finalizeStage8Acceptance(handoffInput), /SOURCE_MISSING/u);
    const finalizationAuthoritySource = buildFinalizationAuthorityFixture(handoffInput);
    const finalization = finalizeStage8Acceptance({
      ...handoffInput,
      finalizationAuthoritySource,
    });
    assert.equal(finalization.snapshot.state, 'ACCEPTED');
    assert.equal(finalization.snapshot.decision, 'ACCEPTED');
    assert.equal(finalization.snapshot.gates['GATE-E8-03'], 'PASS');
    assert.equal(finalization.handoff.status, 'READY_FOR_STAGE9');
    assert.equal(finalization.handoff.release.runtimeSha, intake.release.runtimeSha);
    assert.equal(finalization.handoff.release.submissionSha, intake.release.submissionSha);
    assert.equal(
      finalization.handoff.handoffSha256,
      objectSha256(
        Object.fromEntries(
          Object.entries(finalization.handoff).filter(([key]) => key !== 'handoffSha256'),
        ),
      ),
    );
    const prematureFinalAuthority = parseStrictJsonSource(finalizationAuthoritySource, {
      scanForbiddenData: false,
    });
    prematureFinalAuthority.approvedAtUtc = '2026-08-18T07:59:59.000Z';
    const prematureFinalBody = Object.fromEntries(
      Object.entries(prematureFinalAuthority).filter(([key]) => key !== 'authoritySha256'),
    );
    prematureFinalAuthority.authoritySha256 = objectSha256(prematureFinalBody);
    assert.throws(
      () =>
        finalizeStage8Acceptance({
          ...handoffInput,
          finalizationAuthoritySource: jsonBytes(prematureFinalAuthority),
        }),
      /E8_FINALIZATION_AUTHORITY_INVALID/u,
    );
    const tamperedFinalAuthority = parseStrictJsonSource(finalizationAuthoritySource, {
      scanForbiddenData: false,
    });
    tamperedFinalAuthority.artifactInventory[0].sources[0].bytes += 1;
    const tamperedFinalBody = Object.fromEntries(
      Object.entries(tamperedFinalAuthority).filter(([key]) => key !== 'authoritySha256'),
    );
    tamperedFinalAuthority.authoritySha256 = objectSha256(tamperedFinalBody);
    assert.throws(
      () =>
        finalizeStage8Acceptance({
          ...handoffInput,
          finalizationAuthoritySource: jsonBytes(tamperedFinalAuthority),
        }),
      /E8_FINALIZATION_AUTHORITY_INVALID/u,
    );
    assert.throws(
      () => createStage8HandoffDraft({ ...handoffInput, snapshot: deriveStage8State({ intake }) }),
      /E8_STAGE9_HANDOFF_PRECONDITION_INVALID/u,
    );

    const rejectedAssessmentValue = rehashAssessment({
      ...acceptedFixture.assessment,
      quality: { ...acceptedFixture.assessment.quality, openP1: 1 },
      decision: 'REJECTED',
      handoffReady: false,
    });
    assert.equal(
      deriveStage8State({ intake, assessment: rejectedAssessmentValue }).state,
      'REJECTED',
    );
    const blockedReport = renderStage8Report(createStage8NotReady());
    assert.equal(blockedReport.includes('BLK-E8-01'), true);
    for (const [index, heading] of STAGE8_REPORT_HEADINGS.entries()) {
      assert.equal(blockedReport.split(`## ${index + 1}. ${heading}`).length, 2);
    }

    return {
      status: 'PASS',
      canaries: 28,
      catalogSha256: STAGE8_CATALOG_SHA256,
      externalNetworkCalls: 0,
      externalMutations: 0,
    };
  } finally {
    const resolvedTemporaryRoot = path.resolve(temporaryRoot);
    const temporaryPrefix = `${path.resolve(os.tmpdir())}${path.sep}`;
    assert.equal(resolvedTemporaryRoot.startsWith(temporaryPrefix), true);
    rmSync(resolvedTemporaryRoot, { recursive: true, force: true });
  }
};
