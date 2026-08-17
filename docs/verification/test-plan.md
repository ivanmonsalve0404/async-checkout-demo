# Etapa 6 — Plan maestro de verificación

<!-- stage6-status-authority: ART-VER-01 SAME_SHA_RUNTIME_MANIFEST -->

## Control

| Campo                 | Valor                                       |
| --------------------- | ------------------------------------------- |
| Artefacto             | `ART-VER-01`                                |
| Estado                | `APPROVED_BY_SAME_SHA_MANIFEST`             |
| Baseline de entrada   | `eaa20ccbb05ab7fdd563009934b25f6c57451311`  |
| Candidato final       | `SHA_BY_SAME_SHA_MANIFEST`                  |
| Entorno por defecto   | `ENV-E6-LOCAL`, fake y red externa denegada |
| Fuente de identidades | `docs/verification/stage6-intake.md`        |
| Evidencia             | `docs/verification/evidence-index.md`       |

Este plan no hereda resultados verdes. Un resultado existe sólo cuando el reporte E6 y su manifiesto comparten `runId` y SHA.

## Objetivo y salida

Verificar el checkout integrado sobre un commit inmutable en once dimensiones: funcional, integración, datos, seguridad, privacidad, resiliencia, compatibilidad, accesibilidad, rendimiento, operabilidad y mantenibilidad. La salida exige cero P0/P1 abiertos y evidencia reproducible/sanitizada.

Sin autorización externa, sandbox, entorno efímero/headers alojados, ZAP, DAST y despliegue cloud permanecen `NOT_RUN_AUTH_REQUIRED`. Esa limitación puede permitir `GATE-E6-03=CONDITIONAL_GO` sólo si todo lo local está en PASS; nunca autoriza release final.

## Suites y vínculo ejecutable

| Nivel                              | Comando raíz vigente o productor                                      | Identidades principales                      | Evidencia E6       | Estado de intake              |
| ---------------------------------- | --------------------------------------------------------------------- | -------------------------------------------- | ------------------ | ----------------------------- |
| Workspace/formato/lint/types/build | `pnpm verify` (incluye controles)                                     | RNF-04/05/08/09/13                           | `EVD-E6-03/04`     | `STATUS_BY_SAME_SHA_MANIFEST` |
| Unit                               | `pnpm test:unit`                                                      | `TC-UNIT-*`; dominio, reducers, casos de uso | `EVD-E6-06/07/10`  | `STATUS_BY_SAME_SHA_MANIFEST` |
| Coverage                           | `pnpm test:coverage`                                                  | RNF-21/22; ≥85 % ×4 por app                  | `EVD-E6-08/09`     | `STATUS_BY_SAME_SHA_MANIFEST` |
| Contract/OpenAPI                   | `pnpm test:contract`; `pnpm openapi:lint`; `pnpm contracts:check`     | `TC-CONTRACT-*`, `TC-INT-01/03/11/12`        | `EVD-E6-05/12`     | `STATUS_BY_SAME_SHA_MANIFEST` |
| Persistencia real local            | `pnpm test:integration`                                               | `TC-INT-05`; transacciones DynamoDB Local    | `EVD-E6-11/15..20` | `STATUS_BY_SAME_SHA_MANIFEST` |
| Fake/E2E heredado                  | `pnpm test:smoke`                                                     | `FAKE-E5-01..12`, `SMK-E5-01..12`            | `EVD-E6-13/14`     | `STATUS_BY_SAME_SHA_MANIFEST` |
| Seguridad estática                 | `pnpm security:secrets`; `pnpm security:dependencies`                 | RNF-06/18..20/26/27                          | `EVD-E6-31/32/35`  | `STATUS_BY_SAME_SHA_MANIFEST` |
| Compatibilidad                     | Productor E6 cross-browser                                            | `UAT-12/15`; `UXVP-01..07`                   | `EVD-E6-25/26`     | `STATUS_BY_SAME_SHA_MANIFEST` |
| Accesibilidad                      | Productor E6 automático + `docs/verification/manual-accessibility.md` | `UAT-16/36`                                  | `EVD-E6-27/28`     | `STATUS_BY_SAME_SHA_MANIFEST` |
| Performance/carga                  | Productor E6 lab/carga local                                          | `UAT-12/46`; presupuestos E2                 | `EVD-E6-29/30`     | `STATUS_BY_SAME_SHA_MANIFEST` |
| UAT                                | Procedimientos de `uat-results.md`                                    | `UAT-01..48`                                 | `EVD-E6-36`        | `STATUS_BY_SAME_SHA_MANIFEST` |
| Sandbox                            | Job separado bajo `AUTH-E6-02`                                        | Contrato real mínimo                         | `EVD-E6-24`        | `NOT_RUN_AUTH_REQUIRED`       |
| Headers/perf alojados              | Entorno efímero propio bajo `AUTH-E6-01`                              | Edge/target propio                           | `EVD-E6-29/34`     | `NOT_RUN_AUTH_REQUIRED`       |
| ZAP baseline propio                | Job separado bajo `AUTH-E6-03`                                        | OWASP/target propio                          | `EVD-E6-33`        | `NOT_RUN_AUTH_REQUIRED`       |
| DAST activo propio                 | Job separado bajo `AUTH-E6-04`                                        | Target aislado y scope acordado              | N/A                | `NOT_RUN_AUTH_REQUIRED`       |

`docs/build/test-catalog.json` es el índice mecánico de los 38 IDs E5: cada entrada ejecutable declara runner, archivo y patrón resoluble. Los dos casos diferidos (`TC-INT-13`, `TC-CONTRACT-04`) conservan su autoridad `ADR-09`; no se reemplazan por mocks que aparenten integración real.

## Secuencia

| Fase                    | Entrada                 | Ejecución mínima                                             | Salida                                    |
| ----------------------- | ----------------------- | ------------------------------------------------------------ | ----------------------------------------- |
| 6.0 Readiness           | Rama preparada          | Reconciliar IDs, registrar auth, congelar SHA/lock/toolchain | Baseline `FROZEN`                         |
| 6.1 Estático/unit       | Baseline frozen         | Formato, lint, boundaries, types, unit, coverage, build      | Sin error y ≥85 % ×4                      |
| 6.2 Integración         | 6.1 verde               | OpenAPI, contract, DynamoDB Local, fake                      | Drift 0; efectos/invariantes comprobados  |
| 6.3 E2E/resiliencia     | Sistema local integrado | Smokes, negativos, refresh, multitab, fallos                 | Suites deterministas; flaky crítico 0     |
| 6.4 Compatibilidad/a11y | Build estable           | Tres motores, siete viewports, axe + manual                  | P0/P1 0                                   |
| 6.5 Perf/security       | Target local/propio     | Lab, carga ligera, scans; DAST sólo autorizado               | Presupuestos y severidades dentro de gate |
| 6.6 Sandbox             | `AUTH-E6-02`            | Smoke bajo volumen                                           | PASS o `NOT_RUN_AUTH_REQUIRED`            |
| 6.7 UAT                 | Candidato estable       | 48 casos canónicos                                           | P0/P1 100 % PASS; P2 decidido             |
| 6.8 Regresión           | Correcciones cerradas   | Full regression sobre SHA final                              | P0/P1 0, flaky crítico 0                  |
| 6.9 Gates               | Índice completo         | Evaluar E6-01/02/03 sin heredar PASS                         | Handoff honesto                           |

## Reglas de ejecución

- La misma unidad que se integra no se mockea.
- Se prueban efectos y ausencia de efectos: cobro lógico, stock, reserva, entrega y nueva llamada externa.
- Un retry sólo diagnostica. Fallo inicial + éxito al retry = `FLAKY`, no PASS.
- Dinero, idempotencia, stock y seguridad no se omiten ni se ponen en cuarentena.
- Cada corrección usa `CHG-E6-*`, nuevo SHA, matriz de impacto y regresión.
- `.only` falla la campaña; un skip requiere ID, owner, motivo y fecha.
- La evidencia no contiene secretos, PII real, PAN/CVC/vencimiento, tokens ni payloads completos.

## Gates mecanizables

| Gate         | Condiciones que deben resolver a PASS                                                                                                                             | Estado inicial                                                      |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `GATE-E6-01` | SHA/lock frozen; clon limpio; estático/unit/build; coverage ≥85 % ×4; drift 0; integration/contract; fake 12/12; smoke 12/12; secretos 0; P0/P1 0                 | `STATUS_BY_SAME_SHA_MANIFEST`                                       |
| `GATE-E6-02` | Negativos e integridad 12/12; duplicados/stock negativo/entrega en fallo 0; recovery; browsers/viewports; a11y; perf; seguridad; fuga de datos 0; flaky crítico 0 | `STATUS_BY_SAME_SHA_MANIFEST`; DAST externo `NOT_RUN_AUTH_REQUIRED` |
| `GATE-E6-03` | UAT P0/P1 100 %; P2 decidido; regresión; artefactos 18/18; evidencias 40/40 o N/A aprobado; trazabilidad/rúbrica/handoff                                          | `STATUS_BY_SAME_SHA_MANIFEST`; sandbox `NOT_RUN_AUTH_REQUIRED`      |

No se permite `CONDITIONAL_GO` en E6-01. E6-02 sólo puede condicionarse por target externo no autorizado. E6-03 sólo puede condicionarse por sandbox y/o target QA externo no autorizado, con todas las comprobaciones locales en PASS.
