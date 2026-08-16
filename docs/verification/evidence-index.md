# Etapa 6 — Índice de evidencias sanitizadas

<!-- stage6-status-authority: ART-VER-16 SAME_SHA_RUNTIME_MANIFEST -->

## Control

| Campo      | Valor                                                          |
| ---------- | -------------------------------------------------------------- |
| Artefacto  | `ART-VER-16`                                                   |
| Estado     | `COMPLETE_BY_SAME_SHA_MANIFEST`                                |
| Evidencias | `EVD-E6-01..40` exactas                                        |
| Runtime    | `output/evidence/runtime/stage-6/` (no versionado)             |
| Promoción  | Índices/manifiesto sanitizados bajo `output/evidence/stage-6/` |
| Candidato  | `SHA_BY_SAME_SHA_MANIFEST`                                     |

Una fila sólo puede pasar a PASS/VERIFIED si el artefacto registra `runId`, SHA, UTC, entorno, herramienta/versión, comando/procedimiento, datos sintéticos, resultado, sanitización, defecto aplicable y checksum. Los reportes E5 sirven como antecedente, no como ejecución E6.

## Catálogo `EVD-E6-01..40`

| ID          | Control                             | Productor/ruta esperada                     | Estado                          | Run / SHA / checksum                                                                         |
| ----------- | ----------------------------------- | ------------------------------------------- | ------------------------------- | -------------------------------------------------------------------------------------------- |
| `EVD-E6-01` | Entrada y `GATE-E5-03` reconciliado | `stage6-intake.md`; reporte E6              | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-02` | SHA, lock y árbol congelados        | preflight; `environments.md`                | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-03` | Fresh clone/instalación             | preflight en clon limpio                    | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-04` | Lint/format/typecheck/build         | `pnpm verify:stage6`/CI                     | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-05` | OpenAPI/drift                       | contract report                             | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-06` | Unit frontend                       | test report E6                              | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-07` | Unit backend                        | test report E6                              | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-08` | Coverage web ≥85 % ×4               | coverage summary E6                         | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-09` | Coverage API ≥85 % ×4               | coverage summary E6                         | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-10` | Branches críticas                   | unit/contract/integrity reports             | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-11` | Repositorios/transacciones          | DynamoDB Local/integrity report             | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-12` | Contract fake/provider              | contract report                             | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-13` | Fake 12/12                          | fake report E6                              | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-14` | `SMK-E5-*` 12/12                    | smoke report E6                             | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-15` | Aprobado atómico/único              | integrity report                            | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-16` | Fallos liberan/sin entrega          | integrity/resilience report                 | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-17` | Timeout/unknown/reconcile           | resilience report                           | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-18` | Doble clic/replay                   | integrity report                            | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-19` | Último stock/concurrencia           | integrity/load report                       | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-20` | Quote stale/manipulada              | negative-boundaries report                  | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-21` | Refresh por paso                    | compatibility/recovery report               | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-22` | Refresh en PENDING                  | resilience/recovery report                  | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-23` | Multitab/active transaction         | compatibility/integrity report              | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-24` | Sandbox smoke o bloqueo             | `environments.md`; job sandbox separado     | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-25` | Chromium/Firefox/WebKit             | compatibility report                        | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-26` | Siete viewports                     | compatibility report                        | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-27` | Axe critical/serious = 0            | accessibility report                        | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-28` | Teclado/foco/lectura manual         | `docs/verification/manual-accessibility.md` | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-29` | Lighthouse/budgets                  | performance report                          | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-30` | Carga ligera/rate limit             | load report                                 | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-31` | Secret scan árbol/historial         | security report                             | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-32` | Dependency/SAST/IaC                 | security report                             | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-33` | ZAP baseline propio                 | job DAST separado                           | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-34` | Headers/cookies/CORS/CSP            | HTTP negative specs; edge QA separado       | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-35` | Storage/log/network                 | privacy/security report                     | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-36` | UAT P0/P1                           | `uat-results.md`                            | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-37` | P0/P1 abiertos = 0                  | `defects.md`                                | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-38` | Flaky crítico = 0                   | test reports/defects                        | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-39` | Rúbrica 100+bonus                   | `rubric-scorecard.md`                       | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-40` | Gate E6-03/handoff                  | reporte ejecutado E6                        | `COMPLETE_BY_SAME_SHA_MANIFEST` | `RUN_ID_BY_SAME_SHA_MANIFEST` / `SHA_BY_SAME_SHA_MANIFEST` / `CHECKSUM_BY_SAME_SHA_MANIFEST` |

## Manifiesto `ART-VER-01..18`

| ID           | Artefacto         | Ruta                                         | Estado                          |
| ------------ | ----------------- | -------------------------------------------- | ------------------------------- |
| `ART-VER-01` | Plan maestro      | `docs/verification/test-plan.md`             | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-02` | Entornos/baseline | `docs/verification/environments.md`          | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-03` | Trazabilidad      | `docs/verification/traceability.md`          | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-04` | Tests             | runtime/promoción E6                         | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-05` | Coverage          | runtime/promoción E6                         | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-06` | E2E fake          | runtime/promoción E6                         | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-07` | Sandbox           | job separado                                 | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-08` | Integridad        | runtime/promoción E6                         | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-09` | Compatibilidad    | runtime/promoción E6                         | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-10` | Accesibilidad     | runtime/promoción E6                         | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-11` | Rendimiento       | runtime/promoción E6                         | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-12` | Seguridad         | runtime/promoción E6                         | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-13` | Observabilidad    | runtime/promoción E6                         | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-14` | UAT               | `docs/verification/uat-results.md`           | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-15` | Defectos          | `docs/verification/defects.md`               | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-16` | Índice            | `docs/verification/evidence-index.md`        | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-17` | Rúbrica           | `docs/verification/rubric-scorecard.md`      | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `ART-VER-18` | Reporte/handoff   | `output/etapa-6-integracion-verificacion.md` | `COMPLETE_BY_SAME_SHA_MANIFEST` |

## Sanitización y publicación

- Runtime, traces, videos y bodies completos no se versionan.
- La promoción contiene sólo métricas, estados, IDs, comandos seguros, hashes y referencias relativas.
- Antes de promover se busca PAN/CVC/vencimiento, tokens, secretos, capability cruda, direcciones/emails y payloads del provider.
- Un link externo siempre tiene resumen offline; un artifact HTML comprimido tiene índice y checksum.
- La ausencia de un archivo requerido falla el cierre; no se sustituye con texto “PASS”.
