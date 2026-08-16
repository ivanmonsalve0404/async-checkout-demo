# Etapa 6 — Entornos, baseline y datos

<!-- stage6-status-authority: ART-VER-02 SAME_SHA_RUNTIME_MANIFEST -->

## Estado del artefacto

`FROZEN_BY_SAME_SHA_MANIFEST`. `ART-VER-02` sólo queda autorizado cuando el manifiesto runtime del mismo SHA demuestra un working tree limpio. Los datos siguientes identifican el baseline de entrada; el candidato efectivo se obtiene mediante `SHA_BY_SAME_SHA_MANIFEST`.

## Baseline de entrada observada

| Campo                    | Valor                                                          | Estado                           |
| ------------------------ | -------------------------------------------------------------- | -------------------------------- |
| Commit base              | `eaa20ccbb05ab7fdd563009934b25f6c57451311`                     | `RECORDED`                       |
| Rama de trabajo          | `codex/stage-6-integration-verification`                       | `WORKING`                        |
| Upstream del base        | `origin/master`                                                | `RECORDED`                       |
| Lockfile Git blob        | `4e1c01e7b7ebe4686555390b9a70842a64f95bc9`                     | `RECORDED`; recalcular al freeze |
| Node fijado              | `24.19.0` (`.nvmrc`, `.node-version`, engines)                 | `REQUIRED`                       |
| Node observado en intake | `24.4.1`                                                       | `MISMATCH`; no usar para gate    |
| pnpm fijado/observado    | `11.19.0`                                                      | `MATCH`                          |
| OpenAPI                  | `3.1.2`; 14 operaciones                                        | `BASELINE_AVAILABLE`             |
| Jest API/Web             | Umbral global ≥85 % en statements, branches, functions y lines | `CONFIGURED`                     |
| Adapter de datos         | memory o DynamoDB Local                                        | `LOCAL_ONLY`                     |
| Adapter de pago          | fake por defecto                                               | `LOCAL_ONLY`                     |
| Sandbox                  | `READY_DISABLED`                                               | `NOT_RUN_AUTH_REQUIRED`          |
| Webhook real             | `ADR-09 BLOCKED`; `API-11 DEFERRED_P1`                         | `NOT_RUN_AUTH_REQUIRED`          |
| Working tree             | Evaluado por el manifiesto runtime del candidato               | `STATUS_BY_SAME_SHA_MANIFEST`    |

## Freeze del candidato

Antes de ejecutar la campaña final se debe sustituir la baseline de entrada por una fila de ejecución con:

| Campo obligatorio  | Fuente mecánica                                        | Criterio                                           |
| ------------------ | ------------------------------------------------------ | -------------------------------------------------- |
| SHA y rama/tag     | `git rev-parse HEAD`; `git branch --show-current`      | SHA único y árbol limpio                           |
| Lockfile           | `git hash-object pnpm-lock.yaml`                       | Hash ligado al mismo SHA                           |
| Toolchain          | `node --version`; `pnpm --version`                     | Node 24.19.0, pnpm 11.19.0                         |
| Instalación        | `pnpm install --frozen-lockfile` en clon nuevo         | Exit 0                                             |
| Browser/Playwright | versión del runner y tres motores realmente instalados | Registrar cada versión; no inferir por dependencia |
| Configuración      | hashes de Jest, OpenAPI y scripts de verificación      | Mismo snapshot que el SHA                          |
| Evidencia          | manifiesto E6                                          | Todos los reportes declaran el SHA final           |

Un cambio posterior invalida únicamente las evidencias afectadas, crea un candidato nuevo y obliga a reejecutar gates.

## Matriz de entornos

| ID             | Provider                  | Mutación permitida                            | Estado actual           | Uso autorizado                                                                       |
| -------------- | ------------------------- | --------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------ |
| `ENV-E6-LOCAL` | Fake                      | Archivos/servicios locales y datos sintéticos | `AVAILABLE`             | Unit, component, integration, contract, E2E, a11y, perf local y carga ligera aislada |
| `ENV-E6-CI`    | Fake                      | Recursos efímeros del job                     | `AVAILABLE_AFTER_PUSH`  | Gates automáticos y artefactos sanitizados                                           |
| `ENV-E6-QA`    | Fake/sandbox configurable | Sólo target propio con autorización explícita | `NOT_RUN_AUTH_REQUIRED` | Cross-browser remoto, headers, DAST y performance estable                            |
| `ENV-E6-SBX`   | Sandbox externo           | Bajo volumen y límites aprobados              | `NOT_RUN_AUTH_REQUIRED` | Smoke contractual, nunca carga ni DAST                                               |

## Autorizaciones

| ID           | Operación                                     | Estado        | Regla                                               |
| ------------ | --------------------------------------------- | ------------- | --------------------------------------------------- |
| `AUTH-E6-01` | Crear o usar un entorno efímero propio        | `NOT_GRANTED` | Cero provisión, coste o mutación externa            |
| `AUTH-E6-02` | Ejecutar smoke y transacción sandbox          | `NOT_GRANTED` | Cero request o transacción externa                  |
| `AUTH-E6-03` | Ejecutar ZAP baseline pasivo en target propio | `NOT_GRANTED` | No iniciar el escáner ni dirigir tráfico a terceros |
| `AUTH-E6-04` | Ejecutar DAST activo en target propio aislado | `NOT_GRANTED` | Prohibido sin excepción explícita y scope acordado  |

Crear/usar un entorno efímero, medir performance alojado y revisar sus headers requieren `AUTH-E6-01` y, para cloud/HTTPS y `UAT-33`, la ejecución de Etapa 7. `AUTH-E6-03` autoriza exclusivamente ZAP baseline pasivo; `AUTH-E6-04` queda reservado al DAST activo.

## Variables públicas requeridas

Se registran nombres, nunca valores secretos: `APP_ENV`, `API_PORT`, `API_BASE_PATH`, `ALLOWED_ORIGIN`, `LOG_LEVEL`, `DATA_ADAPTER`, `DYNAMODB_ENDPOINT`, `CATALOG_TABLE_NAME`, `CHECKOUT_TABLE_NAME`, `RUNTIME_SECURITY_ROOT_KEY`, `PRODUCT_SEED_ID`, `PRODUCT_INITIAL_STOCK`, `CHECKOUT_TTL_SECONDS`, `PAYMENT_ADAPTER`, `PAYMENTS_ENABLED`, `TOKENIZATION_MODE`, `FAKE_PAYMENT_SCENARIO`, `FAKE_RECONCILE_INTERVAL_MS`, `QUOTE_TTL_SECONDS`, `VITE_API_BASE_URL`, `VITE_PRODUCT_ID`.

Los valores locales no pueden autorizar un provider real. `RUNTIME_SECURITY_ROOT_KEY` se inyecta fuera de Git cuando se usa DynamoDB Local.

## Datos sintéticos e aislamiento

| Control     | Regla verificable                                                                |
| ----------- | -------------------------------------------------------------------------------- |
| Namespace   | `runId` único por ejecución y referencia idempotente por escenario               |
| Producto    | `product-demo-001` o seed equivalente bajo autoridad backend                     |
| Persona     | Nombre/dirección ficticios y email de dominio no entregable                      |
| Pago        | Alias del fake; tarjeta sólo si un sandbox autorizado publica un fixture vigente |
| Tiempo      | Reloj inyectado por test; nunca reloj global compartido                          |
| Stock único | Suite serial o barrera explícita; cleanup por namespace                          |
| Evidencia   | Sin PAN, CVC, vencimiento, tokens, secretos, bodies completos ni PII real        |
| Cleanup     | Local/efímero, idempotente y limitado al `runId`                                 |

## Viewports y presupuestos congelados

| ID        | Viewport |
| --------- | -------- |
| `UXVP-01` | 320×568  |
| `UXVP-02` | 375×667  |
| `UXVP-03` | 390×844  |
| `UXVP-04` | 667×375  |
| `UXVP-05` | 768×1024 |
| `UXVP-06` | 1334×750 |
| `UXVP-07` | 1440×900 |

Presupuestos E2: imagen principal ≤120 KiB, LCP <2.5 s, CLS <0.1, INP ≤200 ms y dimensiones/media reservadas al 100 %. Son objetivos de laboratorio hasta que una evidencia E6 los mida; no se presentan como datos de campo.
