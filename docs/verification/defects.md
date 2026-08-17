# Etapa 6 — Defectos, regresiones y flakiness

<!-- stage6-status-authority: ART-VER-15 SAME_SHA_RUNTIME_MANIFEST -->

## Estado

`CLOSED_OR_ACCEPTED_BY_SAME_SHA_MANIFEST`. El registro versionado conserva `DEF-E6-01`, `DEF-E6-02`, `DEF-E6-03`, `DEF-E6-04`, `DEF-E6-05`, `DEF-E6-06` y `DEF-E6-07` con su causa y regresión; su cierre efectivo y `EVD-E6-37/38` sólo los autoriza el manifiesto runtime del mismo SHA.

## Registro

| ID          | Título                                                                | Severidad                            | Requisito/AC/UAT                       | Entorno/SHA                                | Pasos                                                                                  | Esperado/actual                                                                        | Evidencia                                               | Causa                                                                                           | Owner   | Estado                          | Fix SHA                    | Regresión                                      | Re-run                        | Gate                                       |
| ----------- | --------------------------------------------------------------------- | ------------------------------------ | -------------------------------------- | ------------------------------------------ | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------- | ------------------------------- | -------------------------- | ---------------------------------------------- | ----------------------------- | ------------------------------------------ |
| `DEF-E6-01` | El foco se pierde al resolver superficies asíncronas del diálogo      | P1 accesibilidad                     | RNF-03; SC-EN-02-01; UAT-16/36         | `ENV-E6-LOCAL`; `SHA_BY_SAME_SHA_MANIFEST` | Abrir durante carga y resolver checkout/config sin cambiar de step                     | Esperado: heading nuevo enfocado; actual: `BODY`                                       | `CHG-E6-02`; spec diálogo; axe E6                       | El effect dependía sólo de `progress.step`, no de la superficie asíncrona                       | UX/QA   | `VERIFIED_BY_SAME_SHA_MANIFEST` | `SHA_BY_SAME_SHA_MANIFEST` | 19/19 focal + axe 0 violaciones                | `STATUS_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST`; E6-02/03    |
| `DEF-E6-02` | Recovery/final renavega continuamente a la misma ruta de estado       | P1 funcional/rendimiento             | RF-12/13; AC-US-09-02/12-01; UAT-27/31 | `ENV-E6-LOCAL`; `SHA_BY_SAME_SHA_MANIFEST` | Recuperar una transacción final ya ubicada en su ruta canónica y renderizar el diálogo | Esperado: no renavegar; actual: `onStatusRoute` se invocaba en cada render             | `CHG-E6-04`; spec diálogo; Lighthouse focal             | Faltaban guardas de igualdad de `progress.transactionId` y `mode !== 'status'`                  | UX/QA   | `VERIFIED_BY_SAME_SHA_MANIFEST` | `SHA_BY_SAME_SHA_MANIFEST` | 19/19 focal; Lighthouse final PASS             | `STATUS_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST`; E6-02/03    |
| `DEF-E6-03` | Narrador comunica importes COP como dólares                           | P1 accesibilidad/claridad financiera | RNF-03; A11Y-MAN-01-C01; UAT-16        | `ENV-E6-LOCAL`; `SHA_BY_SAME_SHA_MANIFEST` | Recorrer precio, resumen y CTA de pago con Narrador                                    | Esperado: pesos colombianos; actual: el símbolo de moneda se anunciaba como dólares    | `CHG-E6-05`; specs de precio/resumen; revisión Narrador | El nombre accesible reutilizaba el símbolo visual ambiguo sin nombrar la moneda COP             | UX/QA   | `VERIFIED_BY_SAME_SHA_MANIFEST` | `SHA_BY_SAME_SHA_MANIFEST` | 22/22 focal + nombres accesibles COP           | `STATUS_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST`; E6-02/03    |
| `DEF-E6-04` | Etiquetas ARIA sobre elementos genéricos no portables                 | P1 accesibilidad/robustez            | RNF-03; A11Y-MAN-01-C01; UAT-16        | `ENV-E6-LOCAL`; `SHA_BY_SAME_SHA_MANIFEST` | Ejecutar axe sobre precio y captura de pago                                            | Esperado: semántica válida; actual: `aria-label` requería revisión por soporte         | `CHG-E6-06`; specs focales; axe 14/14                   | Se aplicó `aria-label` a un párrafo y a un grupo genérico sin rol compatible                    | UX/QA   | `VERIFIED_BY_SAME_SHA_MANIFEST` | `SHA_BY_SAME_SHA_MANIFEST` | 15/15 focal; avisos ARIA 3 → 0                 | `STATUS_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST`; E6-02/03    |
| `DEF-E6-05` | Sanitización incompleta de comentarios HTML en reporte autoritativo   | P1 seguridad/robustez                | EVD-E6-31/35/40; ART-VER-18            | `ENV-E6-CI`; `SHA_BY_SAME_SHA_MANIFEST`    | CodeQL analiza el recorte de secciones del reporte                                     | Esperado: rechazar comentarios; actual: regex podía dejar un marcador incompleto       | `CHG-E6-07`; CodeQL PR 5; self-tests documentales       | Se intentaba retirar comentarios con una expresión parcial en vez de fallar cerrado             | QA/Sec  | `VERIFIED_BY_SAME_SHA_MANIFEST` | `SHA_BY_SAME_SHA_MANIFEST` | Comentario completo/anidado/abierto rechazado  | `STATUS_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST`; E6-01/02/03 |
| `DEF-E6-06` | Lighthouse no inicia Chromium en el runner Linux de CI                | P1 verificación/rendimiento          | RNF-03/15; UAT-12; EVD-E6-29/36        | `ENV-E6-CI`; `SHA_BY_SAME_SHA_MANIFEST`    | Ejecutar la matriz Lighthouse mediante Puppeteer en Ubuntu CI                          | Esperado: 14 auditorías; actual: fallo de sandbox antes de publicar la primera muestra | `CHG-E6-08`; artefacto CI; matriz perf local            | Puppeteer no heredaba la opción de compatibilidad de sandbox usada por Playwright en CI Linux   | QA/Perf | `VERIFIED_BY_SAME_SHA_MANIFEST` | `SHA_BY_SAME_SHA_MANIFEST` | Canarios Linux CI/local/no Linux + matriz PASS | `STATUS_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST`; E6-02/03    |
| `DEF-E6-07` | El paso de tarjeta queda en Protegiendo método bajo React Strict Mode | P1 funcional/accesibilidad           | RNF-03; UAT-16; A11Y-MAN-01/03         | `ENV-E6-LOCAL`; `SHA_BY_SAME_SHA_MANIFEST` | Completar una tarjeta sintética en desarrollo con Strict Mode y continuar              | Esperado: avanzar a datos; actual: la respuesta del token fake se ignoraba             | `CHG-E6-09`; spec Strict Mode; revisión Narrador        | El cleanup de prueba marcaba el componente desmontado y el segundo setup no restauraba la marca | UX/QA   | `VERIFIED_BY_SAME_SHA_MANIFEST` | `SHA_BY_SAME_SHA_MANIFEST` | Focal 8/8 y web 113/113                        | `STATUS_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST`; E6-02/03    |

El siguiente hallazgo usa `DEF-E6-08`. No crear IDs para bloqueos de autorización.

## Control de cambios

| ID                 | Motivo y autoridad                                                                   | Artefactos afectados                      | Reejecución obligatoria                      | SHA                        | Estado                        |
| ------------------ | ------------------------------------------------------------------------------------ | ----------------------------------------- | -------------------------------------------- | -------------------------- | ----------------------------- |
| `CHG-E6-01`        | Reconciliar E5 tras merge y cuatro checks verdes; regla de entrada E6                | Intake y gate heredado                    | Preflight                                    | `eaa20cc`                  | `VERIFIED`                    |
| `CHG-E6-02`        | Corregir `DEF-E6-01` en la superficie común de foco; §37.1                           | Diálogo y regresión de foco/axe           | A11y, UAT-16/36 y full regression            | `SHA_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST` |
| `CHG-E6-03`        | Retirar `@lhci/cli@0.15.0` por dos HIGH transitivas y usar Lighthouse 13.4.1 directo | `package.json`, lockfile y runner de perf | Audit dev+prod, perf y full regression       | `SHA_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST` |
| `CHG-E6-04`        | Evitar la renavegación repetida de la ruta final y cerrar `DEF-E6-02`; §37.1         | Diálogo y regresión de status/recovery    | Lighthouse, UAT-27/31 y full regression      | `SHA_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST` |
| `CHG-E6-05`        | Nombrar explícitamente COP para tecnología de asistencia y cerrar `DEF-E6-03`        | Precio, resumen y CTA de pago             | A11y manual/auto, UAT-16 y full regression   | `SHA_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST` |
| `CHG-E6-06`        | Reemplazar etiquetas ARIA no portables y cerrar `DEF-E6-04`                          | Precio y agrupación de captura            | A11y manual/auto, UAT-16 y full regression   | `SHA_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST` |
| `CHG-E6-07`        | Rechazar comentarios HTML en secciones autoritativas y cerrar `DEF-E6-05`            | Validador documental y canarios           | CodeQL, closeout self-test y full regression | `SHA_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST` |
| `CHG-E6-08`        | Ajustar sólo Puppeteer en Linux CI para cerrar `DEF-E6-06`                           | Runner Lighthouse y canarios de entorno   | Performance, UAT-12 y full regression        | `SHA_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST` |
| `CHG-E6-09`        | Restaurar la marca mounted en cada setup de Strict Mode y cerrar `DEF-E6-07`         | Paso de tarjeta y spec Strict Mode        | Web, A11y manual y full regression           | `SHA_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST` |
| `CHG-E6-UAT-22-45` | Aplicar `CHG-16` y OpenAPI a ERR-12/13 postaceptación                                | UAT-22/45 y su runner                     | UAT-22/45 y full UAT                         | `SHA_BY_SAME_SHA_MANIFEST` | `STATUS_BY_SAME_SHA_MANIFEST` |

## Bloqueos externos (no defectos)

| Bloqueo                    | Estado         | Afecta                          | Tratamiento                                       |
| -------------------------- | -------------- | ------------------------------- | ------------------------------------------------- |
| Sandbox externo            | `BLOCKED_AUTH` | `EVD-E6-24` y smoke contractual | `NOT_RUN_AUTH_REQUIRED`; cero request             |
| Target QA propio/DAST/edge | `BLOCKED_AUTH` | `EVD-E6-33` y parte edge de 34  | `NOT_RUN_AUTH_REQUIRED`; no escanear terceros     |
| Cloud/HTTPS                | `BLOCKED_AUTH` | `UAT-33`, etapa 7               | `NOT_RUN_AUTH_REQUIRED`; cero deploy              |
| `ADR-09`                   | `BLOCKED`      | Adapter/captura/webhook reales  | Mantener fake y fail-closed; no inventar contrato |

## Flujo y política

`NEW → TRIAGED → IN_PROGRESS → FIXED → VERIFIED → CLOSED`.

Estados alternos: `DUPLICATE`, `NOT_REPRODUCIBLE` con evidencia, `ACCEPTED_RISK` sólo P2/P3, `BLOCKED_AUTH` y `REOPENED`.

- P0/P1 abiertos al release: 0; nunca se aceptan como riesgo.
- Un fix crea nuevo candidato, invalida evidencia afectada y agrega regresión automática cuando sea técnicamente posible.
- “No volvió a pasar” no cierra un defecto sin causa o hipótesis sustentada y reejecución.
- Un fallo inicial que pasa al retry es `FLAKY`; no cuenta como PASS.
- Flaky P0/P1 falla el gate; flaky P2 requiere defecto, owner y fecha corta.
- Dinero, idempotencia, stock y seguridad nunca se omiten ni se ponen en cuarentena.

## Resumen de cierre

| Métrica                    | Umbral | Estado actual                 |
| -------------------------- | -----: | ----------------------------- |
| P0 abiertos                |      0 | `STATUS_BY_SAME_SHA_MANIFEST` |
| P1 abiertos                |      0 | `STATUS_BY_SAME_SHA_MANIFEST` |
| P2 sin aceptación          |      0 | `STATUS_BY_SAME_SHA_MANIFEST` |
| Flaky crítico              |      0 | `STATUS_BY_SAME_SHA_MANIFEST` |
| Fixes sin regresión/re-run |      0 | `STATUS_BY_SAME_SHA_MANIFEST` |
