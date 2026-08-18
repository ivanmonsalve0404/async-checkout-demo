# Etapa 7 — Índice de artefactos y evidencias

<!-- STAGE7_FINAL_AUTHORITY:release-manifest.json -->

Este archivo define únicamente el catálogo estable. El estado final de cada fila es
`STATUS_BY_STAGE7_MANIFEST`: lo decide el manifiesto de release validado, nunca este
documento ni una observación manual sin evidencia enlazada.

## Artefactos

| ID         | Artefacto                 | Contenido mínimo                                  | Estado                    |
| ---------- | ------------------------- | ------------------------------------------------- | ------------------------- |
| ART-REL-01 | Plan de release           | Alcance, ventana, responsables, aborto y rollback | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-02 | Manifiesto del candidato  | SHA, hashes, tag y toolchain                      | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-03 | Preflight AWS             | Cuenta, región, identidad, cuotas y bootstrap     | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-04 | Paquete IaC               | Synth, tests, plantillas y checksum               | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-05 | Revisión de cambios       | Diff, reemplazos, IAM y aprobación                | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-06 | Identidad de despliegue   | OIDC, roles, trust y permisos                     | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-07 | Reporte DataStack         | Tabla, configuración, seed y verificación         | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-08 | Reporte ApiStack          | API, Lambda, alias, health y outputs              | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-09 | Reporte WebStack          | S3, OAC, CloudFront, assets y configuración       | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-10 | Reporte edge/TLS          | HTTPS, dominio, headers, CORS y caché             | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-11 | Reporte observabilidad    | Logs, métricas, alarmas y dashboard               | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-12 | Reporte costes            | Budget, tags, retención y cleanup                 | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-13 | Smoke post-deploy         | Casos críticos y evidencias                       | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-14 | Validación sandbox        | Smoke autorizado y sanitizado                     | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-15 | Reporte de rollback       | Frontend, API, datos y tiempos                    | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-16 | Seguridad del repositorio | Secret scan, historial y archivos públicos        | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-17 | README y release notes    | URLs, arquitectura, pruebas y operación           | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-18 | Índice de evidencias      | Rúbrica y enlaces trazables                       | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-19 | Evaluación de gates       | Los tres gates de la etapa                        | STATUS_BY_STAGE7_MANIFEST |
| ART-REL-20 | Handoff a etapa 8         | Paquete de aceptación                             | STATUS_BY_STAGE7_MANIFEST |

## Evidencias

| ID        | Evidencia                                          | Estado                    |
| --------- | -------------------------------------------------- | ------------------------- |
| EVD-E7-01 | Autorización de release y alcance                  | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-02 | SHA, tag y lockfile congelados                     | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-03 | Checksums de artefactos                            | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-04 | Toolchain y versiones                              | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-05 | Cuenta y región confirmadas                        | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-06 | Identidad OIDC o sesión temporal                   | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-07 | Bootstrap CDK verificado                           | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-08 | Tests de IaC verdes                                | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-09 | Synth reproducible                                 | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-10 | Diff o change set aprobado                         | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-11 | Reemplazos stateful en cero o aprobación explícita | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-12 | Ampliación IAM revisada                            | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-13 | Referencias de secretos y configuración validadas  | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-14 | DataStack desplegado                               | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-15 | Tabla, cifrado y configuración aprobados           | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-16 | Seed idempotente                                   | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-17 | ApiStack desplegado                                | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-18 | Lambda, versión y alias registrados                | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-19 | Health y readiness de API                          | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-20 | OpenAPI o Swagger público sanitizado               | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-21 | Reconciliador programado verificado                | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-22 | WebStack desplegado                                | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-23 | Bucket no público                                  | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-24 | OAC y policy restringida                           | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-25 | CloudFront HTTPS operativo                         | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-26 | Assets versionados y política de caché             | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-27 | Configuración runtime sin secretos                 | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-28 | CORS exacto                                        | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-29 | Security headers reales                            | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-30 | Cookies reales seguras                             | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-31 | Logs estructurados y redacción                     | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-32 | Dashboard y métricas                               | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-33 | Alarmas verificadas                                | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-34 | Budget y alertas                                   | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-35 | Smoke de catálogo y producto                       | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-36 | Smoke de checkout completo                         | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-37 | Aprobado con stock y entrega únicos                | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-38 | Declined o error sin stock ni entrega              | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-39 | Refresh durante progreso o PENDING                 | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-40 | Replay y doble clic idempotentes                   | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-41 | Smoke sandbox autorizado                           | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-42 | Cross-browser focal post-deploy                    | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-43 | Accesibilidad focal post-deploy                    | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-44 | Lighthouse y rendimiento real                      | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-45 | DAST y headers reales autorizados                  | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-46 | Rollback frontend                                  | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-47 | Rollback API                                       | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-48 | Verificación posterior al rollback                 | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-49 | Re-promoción del candidato                         | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-50 | Secret scan de árbol e historial                   | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-51 | README y URLs finales                              | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-52 | Historial y commits visibles                       | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-53 | Scorecard de rúbrica enlazado                      | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-54 | Cleanup y runbook                                  | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-55 | Primer gate de la etapa                            | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-56 | Segundo gate de la etapa                           | STATUS_BY_STAGE7_MANIFEST |
| EVD-E7-57 | Tercer gate y handoff                              | STATUS_BY_STAGE7_MANIFEST |
