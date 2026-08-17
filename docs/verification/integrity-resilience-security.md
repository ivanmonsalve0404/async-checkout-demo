# Etapa 6 — Protocolo de integridad, resiliencia, carga y seguridad

<!-- STAGE6_FINAL_AUTHORITY:verification-manifest.json -->

## Autoridad y alcance

Este documento describe cómo producir la evidencia; no conserva resultados de una corrida concreta. El estado, el `runId`, el SHA candidato y los checksums se delegan exclusivamente a `output/evidence/stage-6/verification-manifest.json`:

- `RUN_ID_BY_SAME_SHA_MANIFEST`
- `SHA_BY_SAME_SHA_MANIFEST`
- `STATUS_BY_SAME_SHA_MANIFEST`

Los productores locales usan datos sintéticos, procesos nuevos y tráfico sólo loopback. No sustituyen proveedor, sandbox, QA, ZAP o DAST que requieren autorización.

## Reproducción

Usar Node `24.19.0`, pnpm `11.19.0`, dependencias congeladas, contratos y API compilados, y un solo `STAGE6_RUN_ID`:

```powershell
pnpm --filter @checkout/contracts build
pnpm --filter @checkout/api build
pnpm test:integrity
pnpm test:resilience
pnpm test:load
pnpm test:security
```

Cualquier salida técnica distinta de cero, inventario incompleto, evidencia de otro run/SHA, intento de red externa o dato sensible invalida la promoción.

## Inventarios exactos

### Integridad y negativos

- `INT-E6-01..12`: 12 controles exactos, ordenados y únicos.
- `E2E-E6-13..24`: 12 sondas black-box exactas; las suites unit/integration sólo son soporte.
- `UAT-14-IF-01..03`: firma inválida fail-closed, duplicado no-op y final fuera de orden sin efectos.
- Resultado final, stock, entrega, dispatch y reconciliación deben ser atómicos e idempotentes.

### Resiliencia

- `RES-E6-01..17`: 17 escenarios exactos, ordenados y únicos.
- Timeouts, respuesta perdida, estados desconocidos, reintentos y recuperación no pueden duplicar POST ni efectos.
- Los errores deben conservar códigos deterministas y resúmenes sanitizados, sin mensajes, cuerpos o stacks externos.

### Carga ligera

- `LOAD-E6-01..08` y `SCN-E6-LOAD-01..04` exactos.
- Namespace y datasets aislados por `runId`.
- Submit/polling, replay/reconciliación y última unidad con invariantes explícitos.
- `409` y `429` esperados separados de errores técnicos; `Retry-After` obligatorio para rate limit.
- Cero 5xx inesperados, cero error técnico y cero requests externas.

### Seguridad

- `SEC-E6-STATIC-01..06`, `SEC-E6-DYNAMIC-01..08` y cinco controles externos exactos.
- Escaneo de secretos/PAN en árbol e historial, guard de tests enfocados/omitidos, política de permisos mínimos y auditoría completa dev+prod.
- CodeQL sólo se promueve con SARIF same-SHA, cero critical/high/unclassified y runtime fijado.
- Headers, `no-store`, cookies, CORS, CSP, errores RFC 9457, límites de body/content-type y rate limit se validan con sondas locales.
- El escritor de evidencias aplica sanitización fail-closed antes de persistir cada JSON.

## Autorizaciones externas

- `AUTH-E6-01`: target propio HTTPS y UAT alojada.
- `AUTH-E6-02`: sandbox real; sin autorización conserva `ART-VER-07 = NOT_RUN_AUTH_REQUIRED` y sólo permite `CONDITIONAL_GO` no público.
- `AUTH-E6-03`: headers alojados y ZAP baseline pasivo contra target propio.
- `AUTH-E6-04`: DAST activo permanece prohibido salvo autorización separada; nunca se ejecuta por la campaña local.

Una fuente externa configurada pero inválida debe producir FAIL; ausencia conserva `NOT_RUN_AUTH_REQUIRED`. Ningún ingestor realiza red.

## Mapeo de evidencia

| ID              | Fuente canónica                                 | Estado                        |
| --------------- | ----------------------------------------------- | ----------------------------- |
| `ART-VER-08`    | `integrity.json` + `resilience.json`            | `STATUS_BY_SAME_SHA_MANIFEST` |
| `ART-VER-11`    | `load.json`                                     | `STATUS_BY_SAME_SHA_MANIFEST` |
| `ART-VER-12`    | `security.json` + SARIF CodeQL                  | `STATUS_BY_SAME_SHA_MANIFEST` |
| `ART-VER-13`    | `final-artifact-scan.json`                      | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-15..20` | Matrices de integridad, negativos y resiliencia | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-30`     | Perfiles y escenarios de carga                  | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-31`     | Escaneo de árbol/historial y artefactos         | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-32`     | Audit + CodeQL/SARIF same-SHA                   | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-33`     | ZAP pasivo autorizado                           | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-34`     | Headers locales/alojados                        | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-35`     | Sanitización final y logging seguro             | `STATUS_BY_SAME_SHA_MANIFEST` |

El cierre debe rechazar estados documentales que no coincidan con las matrices y checksums del manifiesto same-SHA.
