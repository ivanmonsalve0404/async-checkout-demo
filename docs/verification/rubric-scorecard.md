# Etapa 6 — Scorecard de rúbrica

<!-- stage6-status-authority: ART-VER-17 SAME_SHA_RUNTIME_MANIFEST -->

## Control

| Campo            | Valor                             |
| ---------------- | --------------------------------- |
| Artefacto        | `ART-VER-17`                      |
| Estado           | `CALCULATED_BY_SAME_SHA_MANIFEST` |
| Base potencial   | 100 puntos                        |
| Bonus potencial  | 50 puntos                         |
| Puntaje obtenido | `CALCULATED_BY_SAME_SHA_MANIFEST` |

Los bonus no compensan un criterio base ausente. Un criterio sólo obtiene puntos con evidencia E6 sobre el SHA final; evidencia planificada o heredada no puntúa.

## Scorecard

| ID             | Pts. | Condición objetiva canónica                                                    | Verificación E6                               | Evidencia E6             | Estado                            |              Puntos obtenidos |
| -------------- | ---: | ------------------------------------------------------------------------------ | --------------------------------------------- | ------------------------ | --------------------------------- | ----------------------------: |
| `RUB-BASE-01`  |    5 | README con setup, URLs, arquitectura, datos, cobertura, seguridad y límites    | Fresh clone + inspección/handoff              | `EVD-E6-03/40`           | `CALCULATED_BY_SAME_SHA_MANIFEST` | `POINTS_BY_SAME_SHA_MANIFEST` |
| `RUB-BASE-02`  |    5 | Imagen ≤200 KiB contractual, objetivo E2 ≤120 KiB, dimensiones y cero overflow | Siete viewports + asset + lab                 | `EVD-E6-26/29/36`        | `CALCULATED_BY_SAME_SHA_MANIFEST` | `POINTS_BY_SAME_SHA_MANIFEST` |
| `RUB-BASE-03`  |   20 | Cinco pasos; approved/failed/pending/refresh/stock                             | Fake/E2E/UAT funcional                        | `EVD-E6-13..23/36`       | `CALCULATED_BY_SAME_SHA_MANIFEST` | `POINTS_BY_SAME_SHA_MANIFEST` |
| `RUB-BASE-04`  |   20 | Recursos, HTTP semántico, Swagger y reglas protegidas                          | OpenAPI/contract/negativos/UAT-30             | `EVD-E6-05/11/12/34/36`  | `CALCULATED_BY_SAME_SHA_MANIFEST` | `POINTS_BY_SAME_SHA_MANIFEST` |
| `RUB-BASE-05`  |   30 | Jest FE/BE ≥85 % en cuatro métricas por app                                    | Unit + coverage                               | `EVD-E6-06..10`          | `CALCULATED_BY_SAME_SHA_MANIFEST` | `POINTS_BY_SAME_SHA_MANIFEST` |
| `RUB-BASE-06`  |   20 | SPA/API desplegadas por HTTPS con smoke                                        | Reservado a E7/cloud autorizado               | `EVD-E6-24/40`; `UAT-33` | `CALCULATED_BY_SAME_SHA_MANIFEST` | `POINTS_BY_SAME_SHA_MANIFEST` |
| `RUB-BONUS-01` |   +5 | HTTPS, headers y OWASP sin altos                                               | Seguridad local + DAST/edge propio autorizado | `EVD-E6-31..35`          | `CALCULATED_BY_SAME_SHA_MANIFEST` | `POINTS_BY_SAME_SHA_MANIFEST` |
| `RUB-BONUS-02` |   +5 | Playwright en Chromium/Firefox/WebKit                                          | Cross-browser real                            | `EVD-E6-25/36`           | `CALCULATED_BY_SAME_SHA_MANIFEST` | `POINTS_BY_SAME_SHA_MANIFEST` |
| `RUB-BONUS-03` |  +10 | CSS propio con tokens, Grid/Flex y responsive                                  | Inspección + viewports + motion               | `EVD-E6-26/28/29`        | `CALCULATED_BY_SAME_SHA_MANIFEST` | `POINTS_BY_SAME_SHA_MANIFEST` |
| `RUB-BONUS-04` |  +10 | Lint, módulos, nombres y tests legibles                                        | Verificación estática y revisión              | `EVD-E6-04/38/40`        | `CALCULATED_BY_SAME_SHA_MANIFEST` | `POINTS_BY_SAME_SHA_MANIFEST` |
| `RUB-BONUS-05` |  +10 | Dominio independiente y ports en límites reales                                | Boundaries + integration                      | `EVD-E6-10/11/12`        | `CALCULATED_BY_SAME_SHA_MANIFEST` | `POINTS_BY_SAME_SHA_MANIFEST` |
| `RUB-BONUS-06` |  +10 | Result tipado y errores exhaustivos                                            | Unit/contract + 24 errores                    | `EVD-E6-07/10/12`        | `CALCULATED_BY_SAME_SHA_MANIFEST` | `POINTS_BY_SAME_SHA_MANIFEST` |

## Regla de cálculo

- `VERIFIED` con evidencia completa: asignar todos los puntos de la fila.
- Cualquier estado no verificado, autorización ausente o evidencia sobre otro SHA asigna cero puntos.
- Una excepción P2 aprobada no cambia silenciosamente la condición; documentar su impacto y decisión.
- Reportar por separado `base_obtenida/100` y `bonus_obtenido/50`; nunca sumar bonus para ocultar base incompleta.

El scorecard final debe enlazar los checksums del índice de evidencia y el resultado de `GATE-E6-03`.
