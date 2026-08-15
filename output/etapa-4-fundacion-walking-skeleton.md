# Etapa 4 — Fundación técnica y walking skeleton

## 1. Resumen ejecutivo

La fundación técnica quedó implementada y verificada en modo `local-fake-only`. Existe un monorepo reproducible con React/Redux Toolkit/RTK Query, NestJS con capas y `Result<T, E>`, OpenAPI contract-first, adapters in-memory y DynamoDB local, semilla idempotente, CDK sintetizable, CI sin autoridad cloud, controles de seguridad y un recorrido real navegador → API → caso de uso → repositorio.

| Resultado | Estado |
| --- | --- |
| `pnpm verify` local | `PASS` |
| Clon limpio + instalación congelada + `verify` | `PASS`, 86.4 s, cero cambios tracked |
| Pruebas | API 34/34; web 21/21; IaC 9/9; smoke 6/6 |
| Cobertura API | 97.81 / 93.91 / 100 / 97.47 % |
| Cobertura web | 98.94 / 97.56 / 95.23 / 98.80 % |
| OpenAPI | 14/14 operaciones, 251 refs locales, deriva 0 |
| Secret scan | 0 hallazgos; worktree e historia `PASS` |
| Proveedor/sandbox/AWS | 0 requests, 0 transacciones, 0 deploys |
| `GATE-E4-01` | `PASS`; aprobado por `USER_DECISION_OWNER` el 2026-08-15 |
| `GATE-E4-02` | `PASS`; aprobado por `USER_DECISION_OWNER` el 2026-08-15 |
| `GATE-E4-03` | `BLOCKED`: CI remota verde; branch protection pendiente |

La implementación no habilita pagos, tokenización, sandbox, webhook real, AWS ni etapa 5 formal. El `USER_DECISION_OWNER` aprobó `CHG-17`, las decisiones E4 y los ADR propuestos; `ADR-09` continúa bloqueado para integración real.

## 2. Estado de entrada y prerrequisitos

La instrucción E4 exigía `GATE-E3-03=PASS`; el entregable real E3 declaró `CONDITIONAL_GO_TO_E4_FAKE_ONLY`. El preflight registró `BLK-E4-01` y `CHG-17`: se permitió materializar exclusivamente `E4-EN-01..09` con fake/local, manteniendo `SPK-02`, adapter real, sandbox, webhook y despliegue bloqueados.

| Prerrequisito | Evidencia | Estado |
| --- | --- | --- |
| Entregable E3 disponible | `output/etapa-3-arquitectura-diseno-tecnico.md` | `PASS` |
| Gate E3 literal en `PASS` | E3 dice `CONDITIONAL_GO_TO_E4_FAKE_ONLY` | `BLOCKED`, controlado por `CHG-17` sólo para fake/local |
| OpenAPI accesible | `output/architecture/openapi.yaml` | `PASS` |
| UX disponible | reporte, wireframes y prototipo de E2 | `PASS` |
| Topología y stack utilizables | `DEC-01`, `DEC-02`, ADR E3 + `DEC-E4-01` | `PASS` para foundation |
| Directorio sin secretos | scan inicial y final, valores siempre redaccionados | `PASS` |
| Sin necesidad de cloud/sandbox | adapters local/fake y synth sin deploy | `PASS` |
| Aprobación humana de ADR/P0 | confirmación explícita del `USER_DECISION_OWNER`, 2026-08-15 | `PASS`; `ADR-09` sigue bloqueado para integración real |

Integridad de entrada:

- instrucción E4 SHA-256: `d4bc6a928df81df9b6ac3353f3a74249041173847f2f42eddc39e8cc9f8cf6df`;
- entregable E3 SHA-256: `5b86ce6bf43439eab4534c63d11284840a9df1dd523b2eff5d89b7ec61fffc90`;
- OpenAPI SHA-256: `6bddd9e44e6c1e7c1b8a64bb43600ed8c11e0c7792708ade330ee39e8d84231e`.

## 3. Decisiones aplicadas

| ID | Decisión aplicada | Razón/impacto | Estado |
| --- | --- | --- | --- |
| `CHG-17` | Consumir E3 como `fake-only`; OpenAPI prevalece sobre rutas narrativas; no declarar gates E3 como `PASS` | Resuelve la deriva para construir sin ampliar autoridad; adapter real sigue bloqueado | `CONFIRMED` por `USER_DECISION_OWNER`, 2026-08-15 |
| `DEC-E4-01` | Monorepo mínimo `apps/web`, `apps/api`, `packages/contracts`, `infra`; Node 24.19.0 y pnpm 11.19.0 | Evita paquetes vacíos y congela runtime real disponible | `APPLIED` |
| `DEC-E4-02` | `/api/health` es el health contractual compuesto; no inventar `/health/live` o `/health/ready` | El OpenAPI canónico define una sola ruta que comprueba proceso y repositorio | `APPLIED` |
| `DEC-E4-03` | Validar `ProductResponse` en runtime con Zod además del tipo generado | Un payload 200 inválido cae en estado seguro | `APPLIED` |
| `DEC-E4-04` | Smoke Playwright con API local real para el camino principal e interceptación browser para bordes | Demuestra UX/red sin crear endpoints de test ni contactar terceros | `APPLIED` |
| `DEC-E4-INF-01` | Un `FoundationStack` con fronteras reales | Menos wiring vacío; separación futura sin cambiar contratos | `APPLIED` |
| `DEC-E4-INF-02` | Synth fail-closed: preview/fake/pagos false/tokenización disabled | Impide sintetizar configuración no autorizada | `APPLIED` |
| `DEC-E4-INF-03` | Asset Lambda placeholder marcado `FOUNDATION_SYNTH_ONLY` | Synth reproducible sin presentar el placeholder como aplicación desplegable | `APPLIED` |
| `DEC-E4-INF-04` | Sólo `synth`; Scheduler deshabilitado; sin bootstrap/deploy/destroy/OIDC | Cero mutación cloud | `APPLIED` |

La ubicación de datos quedó en `apps/api/src/infrastructure/persistence` detrás de `CatalogRepository`; no se creó `packages/data` porque aún no existe un segundo consumidor que justifique ese paquete. Es una ubicación permitida por el manifiesto y evita abstracción especulativa.

## 4. Estructura final del repositorio

```text
.
├── .github/
│   ├── workflows/{ci.yml,security.yml}
│   └── pull_request_template.md
├── apps/
│   ├── api/src/{domain,application,infrastructure,interfaces}
│   └── web/src/{app,features,shared}
├── docs/foundation/
│   ├── configuration.md
│   ├── iac-ci-security.md
│   └── toolchain.md
├── infra/{bin,lib,test,assets}
├── packages/contracts/src/{index.ts,generated/openapi.d.ts}
├── scripts/{contracts,security,smoke}
├── output/
│   ├── architecture/openapi.yaml
│   ├── evidence/stage-4/
│   └── etapa-4-fundacion-walking-skeleton.md
├── .editorconfig
├── .env.example
├── .gitattributes
├── .gitignore
├── .node-version
├── .nvmrc
├── eslint.config.mjs
├── package.json
├── pnpm-lock.yaml
├── pnpm-workspace.yaml
├── README.md
└── tsconfig.base.json
```

El repositorio local usa la rama `foundation/stage-4` y commits temáticos. No se creó remoto ni repositorio público.

## 5. Toolchain y versiones

| Componente | Versión efectiva | Control |
| --- | ---: | --- |
| Node.js | `24.19.0` | `.nvmrc`, `.node-version`, engines, script y CI |
| pnpm | `11.19.0` | `packageManager`, engines, script y CI |
| TypeScript | `5.9.3` | pin exacto raíz |
| React | `19.2.8` | pin web |
| Vite | `8.2.1` | pin web |
| Redux Toolkit | `2.12.0` | pin web |
| NestJS | `11.2.1` | pin API |
| Jest | `30.4.2` | pin web/API |
| Playwright Test | `1.61.1` | pin raíz |
| openapi-typescript | `7.13.0` | pin contracts |
| aws-cdk-lib / CDK CLI | `2.265.0` / `2.1136.0` | pins infra |

Existe un solo `pnpm-lock.yaml`, SHA-256 `f17ff6925f909c99e8fb278bcae7573faccbaa2cffcf0348e94484ed1a22ae9d`. La instalación congelada reutilizó 657 paquetes y no alteró el lockfile. `.gitattributes` fija LF y los patrones Jest son independientes de la ruta absoluta.

## 6. Configuración y secretos

Backend, frontend e IaC validan su configuración antes de operar. La combinación aceptada es local/test/preview, `PAYMENT_ADAPTER=fake`, `PAYMENTS_ENABLED=false`, `TOKENIZATION_MODE=disabled` y DynamoDB sólo mediante host local.

| Control | Implementación | Estado |
| --- | --- | --- |
| Defaults no operativos contra terceros | `.env.example` | `PASS` |
| Origen exacto, sin wildcard | schema API | `PASS` |
| Adapter Dynamo remoto rechazado | `app-config.ts` + tests | `PASS` |
| Producción/pagos/tokenización rechazados | schemas API/CDK | `PASS` |
| Secretos y `.env.local` ignorados | `.gitignore` | `PASS` |
| PAN/CVC/token/llaves ausentes de fuentes/builds/evidencia | scanner + historia | `PASS` |
| Logger allowlist/redacción recursiva | `safe-logger.ts` + tests | `PASS` |

No se cargó ninguna credencial, no se leyó el dashboard del proveedor y ningún valor sensible se incluyó en logs, Swagger, fixtures, Git o evidencia.

## 7. Fundación frontend

La SPA usa React, React Router, Redux Toolkit y una única `baseApi` de RTK Query. El slice de producto importa `ProductResponse` generado, codifica el identificador en la URL y valida el payload con Zod antes de renderizar.

Estados implementados y probados:

- carga con `aria-busy` y live region;
- producto disponible con precio COP, stock y media reservada;
- stock cero con acción deshabilitada;
- producto inexistente;
- error temporal con reintento explícito;
- error de contrato no recuperable;
- error boundary global;
- rutas raíz, producto y 404;
- refresh desde backend canónico.

Los tokens de E2 están materializados en CSS mobile-first: foco visible, targets de 44 px, safe area, reduced motion, forced colors, grid desde 768 px y cero assets remotos. El botón de checkout permanece deshabilitado con una explicación visible; no se presenta una feature de pago incompleta.

## 8. Fundación backend

`apps/api` representa físicamente Ports & Adapters:

| Capa | Elementos |
| --- | --- |
| Dominio | `ProductAvailability`, `Money`, invariantes de stock/dinero |
| Aplicación | `Result<T,E>`, combinadores, `GetProductAvailability`, puertos de catálogo/pago |
| Infraestructura | config, logger, memoria, DynamoDB local, seed, fake de pago |
| Interfaces | controladores health/product/docs, presentador, middleware, filtro RFC 9457 |

La API limita bodies a 16 KiB, usa Helmet, CORS exacto, correlación, logs normalizados y errores tipados. `GET /api/health` no expone configuración y sólo responde `ok` cuando el repositorio está listo. `GET /api/v1/products/:productId` atraviesa controlador → caso de uso → puerto → adapter; no existe endpoint de creación de producto.

El port `PaymentProvider` y `FAKE-PAY-01..12` están compilados y probados, pero no se inyectan en un flujo real ni abren red.

## 9. Contratos y OpenAPI

`output/architecture/openapi.yaml` es la única fuente de verdad. `packages/contracts/src/generated/openapi.d.ts` se genera con `openapi-typescript` y no se edita manualmente.

| Verificación | Resultado |
| --- | ---: |
| OpenAPI | `3.1.2` |
| Paths / operaciones / `x-api-id` | 14 / 14 / 14 |
| `$ref` locales resueltos | 251 |
| `$ref` remotos | 0, rechazados por control |
| Catálogo de error | 24/24 |
| Generación repetida | sin cambios |
| Deriva | 0 |
| SHA-256 | `6bddd9e44e6c1e7c1b8a64bb43600ed8c11e0c7792708ade330ee39e8d84231e` |

El contrato HTTP prueba health, producto, 404 RFC 9457 y descarga del OpenAPI. Las rutas narrativas divergentes de E3 no se implementaron; `CHG-17` conserva el OpenAPI como autoridad.

## 10. Datos y semilla

`CatalogRepository` define `findById`, `seedIfAbsent` e `isReady`. Hay dos adapters:

- memoria: default local, clon defensivo e idempotencia;
- DynamoDB: endpoint exclusivamente local, lectura consistente y `Put` condicional.

La semilla `product-demo-001` es determinista, sintética y no contiene PII. Repetirla devuelve `EXISTS` sin sobrescribir. El producto conserva `onHand=3`, `reserved=0`, `available=3`, versión y timestamps canónicos. Tests verifican invariantes, memoria, DynamoDB, factory y semilla.

## 11. Infraestructura como código

`cdk synth --quiet` produjo una plantilla sin lookup ni deploy. La foundation contiene:

- dos Lambda `nodejs24.x` ARM64 con concurrencia acotada;
- dos tablas DynamoDB on-demand y GSI de reconciliación;
- logs JSON con retención de siete días;
- S3 privado con bloqueo público, OAC y CloudFront;
- HTTP API sin CORS permisivo;
- Scheduler `DISABLED`;
- CSP/headers de seguridad y redirect HTTPS.

Las 9 pruebas de IaC pasaron. Hay cero `Resource: "*"` en policies IAM, cero Secrets Manager, cero OIDC y cero comandos de mutación. El placeholder es sólo para synth y debe reemplazarse antes de cualquier despliegue autorizado. CDK informó 81 flags nuevos no fijados; el lock congela esta synth y una actualización futura requiere revisión explícita.

TLS 1.2+ con dominio propio, certificado, Budget y PITR siguen bloqueados por decisiones/autoridad externas. Coste causado por esta etapa: USD 0.

## 12. CI y seguridad

`ci.yml` ejecuta metadata, instalación congelada, browser Chromium y `pnpm verify`; `security.yml` escanea worktree/historia y audita dependencias. Ambos usan `contents: read`, acciones fijadas a SHA, cancelación, timeout y ningún secreto, OIDC o rol AWS.

| Control local | Resultado |
| --- | --- |
| Política de workflows | `PASS`, 2/2 |
| Acciones sin SHA | 0 |
| Permisos write / `pull_request_target` | 0 / 0 |
| Credenciales AWS / contexto secrets | 0 / 0 |
| Scanner self-test | `PASS` |
| Worktree + builds + CloudFormation | `PASS`, 178 archivos en la ejecución final |
| Historia Git | `PASS` |
| Vulnerabilidades high/critical conocidas | 0 / 0 |
| CI remota | `PASS`; workflows `CI` y `Security` verdes en PR #2 |
| Branch protection remota | `PENDING_VERIFICATION` |

El detector PAN exige longitud, Luhn y un MII no cero; esto evita rangos ISO generados sin dejar de detectar el fixture positivo del self-test. Los hallazgos se reportan sólo como archivo/línea/regla.

## 13. Walking skeleton

Camino principal demostrado:

```text
Edge headless → Vite preview → RTK Query → proxy local → Nest controller
→ GetProductAvailability → CatalogRepository → InMemoryCatalogRepository
→ ProductResponse validado en runtime → vista accesible
```

| ID | Escenario | Resultado |
| --- | --- | --- |
| `SMK-E4-01` | producto disponible desde API local real | `PASS` |
| `SMK-E4-02` | stock cero bloquea continuación | `PASS` |
| `SMK-E4-03` | producto inexistente muestra 404 seguro | `PASS` |
| `SMK-E4-04` | fallo temporal permite exactamente un reintento controlado | `PASS` |
| `SMK-E4-05` | refresh recupera el producto canónico | `PASS` |
| `SMK-E4-06` | respuesta 200 inválida cae en error seguro | `PASS` |

Cada contexto fue mobile 390×844 y rechazó cualquier origen HTTP no localhost. `providerRequests=0`. Los resultados sanitizados están en `output/evidence/stage-4/smoke-results.json`.

## 14. Pruebas y cobertura

| Suite | Resultado | Alcance |
| --- | ---: | --- |
| API Jest | 34/34 | dominio, ROP, casos, config, adapters, logger, HTTP/contrato |
| Web Jest | 21/21 | store, RTK, rutas, estados, error boundary, a11y |
| Contrato HTTP | 5/5 | subset API dedicado; también incluido en 34 |
| IaC Node test | 9/9 | config, recursos, IAM y prohibiciones |
| Playwright smoke | 6/6 | recorrido vertical y bordes |

| Aplicación | Statements | Branches | Functions | Lines | Gate |
| --- | ---: | ---: | ---: | ---: | --- |
| API | 97.81 % | 93.91 % | 100 % | 97.47 % | `PASS` |
| Web | 98.94 % | 97.56 % | 95.23 % | 98.80 % | `PASS` |

El umbral bloqueante es 85 % por métrica y aplicación. Los tests verifican comportamiento y ramas de error; no se excluyó lógica de producto para inflar el porcentaje.

## 15. Evidencias

| ID | Evidencia | Resultado/ubicación |
| --- | --- | --- |
| `EVD-E4-01` | árbol del repositorio | §4, `PASS` |
| `EVD-E4-02` | Node/pnpm efectivos | §5, `PASS` |
| `EVD-E4-03` | frozen install | clon limpio, `PASS` |
| `EVD-E4-04` | lint | 0 errores, `PASS` |
| `EVD-E4-05` | typecheck | 0 errores, `PASS` |
| `EVD-E4-06` | frontend tests | 21/21, `PASS` |
| `EVD-E4-07` | backend tests | 34/34, `PASS` |
| `EVD-E4-08` | cobertura | §14 y `coverage/{web,api}`, `PASS` |
| `EVD-E4-09` | builds | API + web; JS 374,856 B, CSS 3,497 B, `PASS` |
| `EVD-E4-10` | OpenAPI/contratos | §9, `PASS` |
| `EVD-E4-11` | CDK synth | `infra/cdk.out`, `PASS_LOCAL_NO_DEPLOY` |
| `EVD-E4-12` | secretos | worktree + historia, 0 hallazgos, `PASS` |
| `EVD-E4-13` | dependencias | 0 high/critical conocidas, `PASS` |
| `EVD-E4-14` | skeleton | JSON smoke + §13, `PASS` |
| `EVD-E4-15` | CI verde remota | `PASS`; runs `31891916679` y `31891916645` sobre `a0f5e81` |
| `EVD-E4-16` | trazabilidad | §16, `PASS` |
| `EVD-E4-17` | decisiones/riesgos/desviaciones | §§3 y 17, `PASS` |

`verification-summary.json` contiene el resumen machine-readable. La evidencia registra estados bloqueados; no convierte una configuración CI local en una ejecución remota.

## 16. Trazabilidad

### 16.1 Objetivos

| Objetivo / fuente | Decisión | Tarea | Archivo/cambio | Prueba | Evidencia | Gate | Estado |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `OBJ-E4-01`, `RNF-13` | `DEC-E4-01` | `FND-06`,`FND-42` | workspace, lock, `.gitattributes` | fresh clone | `EVD-E4-01..03` | E4-01 | `PASS` |
| `OBJ-E4-02` | `DEC-E4-01` | `FND-07` | manifests y version files | workspace check | `EVD-E4-02` | E4-01 | `PASS` |
| `OBJ-E4-03`, `RNF-05` | `DEC-01` | `FND-16..18` | capas físicas y boundary graph | self-test + scan | `EVD-E4-04/05/16` | E4-01 | `PASS` |
| `OBJ-E4-04`, `RNF-11` | `CHG-17` | `FND-12/13` | OAS + generated types | contract/drift | `EVD-E4-10` | E4-01/03 | `PASS` |
| `OBJ-E4-05`, `RF-01`, `AC-US-01-01..03` | `DEC-01` | `FND-27..31` | `apps/web` | web Jest/a11y | `EVD-E4-06/08/09` | E4-02/03 | `PASS` |
| `OBJ-E4-06`, `RNF-04/05` | `DEC-01` | `FND-17..21` | `apps/api` | API Jest/contract | `EVD-E4-07/09` | E4-02/03 | `PASS` |
| `OBJ-E4-07`, `RF-16` | `DEC-E4-01` | `FND-22..26` | port + memory/Dynamo/seed | adapter tests | `EVD-E4-07` | E4-02 | `PASS` |
| `OBJ-E4-08`, `US-01` | `DEC-E4-04` | `FND-32..35` | web/API/smoke | `SMK-E4-01..06` | `EVD-E4-14` | E4-02 | `PASS` |
| `OBJ-E4-09`, `RNF-10` | `DEC-E4-INF-01..04` | `FND-36..38` | `infra` | 9 IaC + synth | `EVD-E4-11` | E4-03 | `PASS` |
| `OBJ-E4-10`, `RNF-08/09` | workflow mínimo | `FND-39/41/43` | CI + root verify | local `verify` | `EVD-E4-04..15` | E4-03 | `BLOCKED` sólo por ejecución remota |
| `OBJ-E4-11`, `RNF-06/13/14/18..20` | fake-only | `FND-03/40/45` | guards/scanners/workflows | self-tests/history | `EVD-E4-12/13` | E4-01/03 | `PASS` |
| `OBJ-E4-12` | `CHG-17` | `FND-44..47` | reporte/handoff | auditoría | `EVD-E4-16/17` | E4-03 | `PASS`; aprobación recibida |

Cobertura de objetivos: 12/12 enlazados; 10 `PASS`, 2 `BLOCKED` con causa y owner.

### 16.2 Artefactos

| ID | Ubicación | Tareas | Evidencia | Estado |
| --- | --- | --- | --- | --- |
| `ART-FND-01` | raíz/workspace | `FND-06` | EVD-01/03 | `IMPLEMENTED` |
| `ART-FND-02` | `docs/foundation/toolchain.md` | `FND-07` | EVD-02 | `APPROVED` |
| `ART-FND-03` | `.env.example`, configuration doc | `FND-11` | EVD-12/17 | `APPROVED` |
| `ART-FND-04` | `apps/web` | `FND-27..31` | EVD-06/08/09 | `GREEN` |
| `ART-FND-05` | `apps/api` | `FND-17..21` | EVD-07/08/09 | `GREEN` |
| `ART-FND-06` | API persistence/seed | `FND-22..26` | EVD-07 | `GREEN` |
| `ART-FND-07` | `packages/contracts` | `FND-12/13` | EVD-10 | `GREEN` |
| `ART-FND-08` | `infra` | `FND-36..38` | EVD-11 | `SYNTHESIZABLE` |
| `ART-FND-09` | `.github/workflows/ci.yml` | `FND-39/41` | EVD-15 | `GREEN_REMOTE` |
| `ART-FND-10` | workflows/scripts security | `FND-40` | EVD-12/13 | `GREEN_LOCAL` |
| `ART-FND-11` | web + API + adapter | `FND-32..35` | EVD-14 | `DEMONSTRATED` |
| `ART-FND-12` | este reporte/evidencias | `FND-44..47` | EVD-16/17 | `APPROVED` |

Cobertura física: 12/12 presentes; aprobación/ejecución remota pendiente donde se indica.

### 16.3 Tareas `FND-01..47`

| ID | Salida verificable | Estado |
| --- | --- | --- |
| `FND-01` | preflight E3 + `BLK-E4-01`/`CHG-17` | `PASS` limitado a fake/local |
| `FND-02` | ADR/decisiones revisados; real adapter sigue bloqueado | `PASS` |
| `FND-03` | scan inicial sin hallazgos | `PASS` |
| `FND-04` | cero sandbox/cloud/proveedor | `PASS` |
| `FND-05` | rama y commits temáticos locales | `PASS` |
| `FND-06` | workspace pnpm | `PASS` |
| `FND-07` | Node/pnpm fijados | `PASS` |
| `FND-08` | TypeScript strict | `PASS` |
| `FND-09` | ESLint/Prettier/imports | `PASS` |
| `FND-10` | scripts raíz | `PASS` |
| `FND-11` | env example + tres validadores | `PASS` |
| `FND-12` | OpenAPI canónico incorporado | `PASS` |
| `FND-13` | tipos generados/drift | `PASS` |
| `FND-14` | Jest web/API | `PASS` |
| `FND-15` | thresholds 85 % × 4 | `PASS` |
| `FND-16` | fronteras + ciclos con self-test | `PASS` |
| `FND-17` | módulos/capas Nest | `PASS` |
| `FND-18` | `Result<T,E>` | `PASS` |
| `FND-19` | health/correlación | `PASS` |
| `FND-20` | lectura de producto | `PASS` |
| `FND-21` | 34 tests API | `PASS` |
| `FND-22` | puerto catálogo | `PASS` |
| `FND-23` | adapter memoria | `PASS` |
| `FND-24` | adapter Dynamo local | `PASS` |
| `FND-25` | seed idempotente | `PASS` |
| `FND-26` | tests adapters/seed | `PASS` |
| `FND-27` | React/Vite | `PASS` |
| `FND-28` | Redux/RTK Query | `PASS` |
| `FND-29` | estados producto | `PASS` |
| `FND-30` | tokens/estructura E2 | `PASS` |
| `FND-31` | 21 tests web | `PASS` |
| `FND-32` | web → API local | `PASS` |
| `FND-33` | validación runtime | `PASS` |
| `FND-34` | smoke 6/6 | `PASS` |
| `FND-35` | refresh/error/retry | `PASS` |
| `FND-36` | CDK app/stack | `PASS` |
| `FND-37` | 9 tests IaC | `PASS` |
| `FND-38` | synth sin deploy | `PASS` |
| `FND-39` | CI creada | `PASS`; ejecución remota separada `BLOCKED` |
| `FND-40` | security controls | `PASS` |
| `FND-41` | artifacts/report paths | `PASS`; upload remoto no ejecutado |
| `FND-42` | fresh clone | `PASS`, commit `de0f58b`, 86.4 s, diff 0 |
| `FND-43` | root verify | `PASS` |
| `FND-44` | trazabilidad | `PASS` |
| `FND-45` | secretos/historia/nombre local neutral | `PASS`; remoto `N/A_JUSTIFIED` |
| `FND-46` | gates evaluados sin autoaprobar | `PASS` |
| `FND-47` | reporte final | `PASS`; aprobación humana pendiente |

Cobertura de tareas: 47/47 con estado; cero `N/A` sin justificación.

### 16.4 Auditoría `FNDAUD-01..30`

| ID | Resultado | Evidencia/observación |
| --- | --- | --- |
| `FNDAUD-01` | `PASS` | un lockfile |
| `FNDAUD-02` | `PASS` | Node/pnpm fijados |
| `FNDAUD-03` | `PASS` | clon verify deja diff 0 |
| `FNDAUD-04` | `PASS` | TS strict |
| `FNDAUD-05` | `PASS` | cycle self-test + grafo 0 |
| `FNDAUD-06` | `PASS` | dominio sin frameworks |
| `FNDAUD-07` | `PASS` | controladores sin adapters/reglas |
| `FNDAUD-08` | `PASS` | Redux/RTK presentes |
| `FNDAUD-09` | `PASS` | ausencia C3/C4/token |
| `FNDAUD-10` | `PASS` | drift 0 |
| `FNDAUD-11` | `PASS` | seed repetido `EXISTS` |
| `FNDAUD-12` | `PASS` | sin POST producto |
| `FNDAUD-13` | `PASS` | health sólo status/timestamp |
| `FNDAUD-14` | `PASS` | logger redactado/testeado |
| `FNDAUD-15` | `PASS` | recorrido cruza capas |
| `FNDAUD-16` | `PASS` | providerRequests 0 |
| `FNDAUD-17` | `PASS` | web ≥85×4 |
| `FNDAUD-18` | `PASS` | API ≥85×4 |
| `FNDAUD-19` | `PASS` | IaC 9/9 |
| `FNDAUD-20` | `PASS` | synth |
| `FNDAUD-21` | `PASS` | workflow policy 2/2 |
| `FNDAUD-22` | `PASS` | cero credenciales AWS |
| `FNDAUD-23` | `PASS` | scanner worktree/history |
| `FNDAUD-24` | `PASS` | cero critical/high conocidas |
| `FNDAUD-25` | `N/A_JUSTIFIED` | remoto público no creado; nombre local neutral |
| `FNDAUD-26` | `PASS` | historial temático auténtico |
| `FNDAUD-27` | `PASS` | README validado en clon |
| `FNDAUD-28` | `PASS` | EVD-01..17 documentadas |
| `FNDAUD-29` | `PASS` | decisiones P0 aprobadas; `ADR-09` bloqueado sólo para integración real |
| `FNDAUD-30` | `BLOCKED` | branch protection pendiente |

## 17. Riesgos, deuda y excepciones

| ID | Estado | Control/residual | Owner / cierre |
| --- | --- | --- | --- |
| `RSK-E4-01` | `CONTROLLED` | `CHG-17`, scope fake-only | ARCH; confirmar antes de E5 |
| `RSK-E4-02` | `MITIGATED` | sólo 4 workspaces reales | ARCH |
| `RSK-E4-03` | `MITIGATED` | tests de conducta y errores | QA |
| `RSK-E4-04` | `CONTROLLED` | puerto común + tests por adapter | ARCH; contract suite común en E5 |
| `RSK-E4-05` | `MITIGATED` | generación determinista/drift | ARCH |
| `RSK-E4-06` | `MITIGATED` | scan worktree + historia | APPSEC |
| `RSK-E4-07` | `MITIGATED` | contents read, sin OIDC/secrets | APPSEC |
| `RSK-E4-08` | `MITIGATED` | checkout visible pero deshabilitado | PRODUCT |
| `RSK-E4-09` | `CONTROLLED` | audit high/critical 0 | APPSEC; continuo |
| `RSK-E4-10` | `MITIGATED` | runtime/lock/line endings/Jest paths | DEVEX |
| `RSK-E4-11` | `CONTROLLED` | safe logger + tests | APPSEC |
| `RSK-E4-12` | `MITIGATED` | RTK consume API local real | FE |
| `RSK-E4-13` | `MITIGATED` | sólo synth, no scripts deploy | CLOUD |
| `RSK-E4-14` | `CONTROLLED` | remoto público neutral y merge con historia preservada | CANDIDATE |
| `RSK-E4-15` | `ACTIVE_BLOCKER` | GATE-E4-03 espera branch protection | repo owner |
| `RSK-E4-16` | `CONTROLLED` | semántica E3→E4 registrada en `CHG-17` | USER_DECISION_OWNER |
| `RSK-E4-17` | `CONTROLLED` | OpenAPI prevalece; narrativa E3 no editada | ARCH |
| `RSK-E4-18` | `MITIGATED` | CI y Security verdes en PR #2 | repo owner |
| `RSK-E4-19` | `BLOCKED` | TLS propio requiere dominio/certificado | CLOUD/APPSEC |
| `RSK-E4-20` | `OPEN_CONTROLLED` | 81 flags CDK congelados por lock | CLOUD; próxima actualización |

Desviaciones controladas:

| Cambio | Antes | Aplicado | Impacto |
| --- | --- | --- | --- |
| `CHG-17` | E4 pedía gates E3 `PASS` y rutas narrativas | ejecución fake-only; OAS canónico | habilita foundation, no adapter real |
| `DEV-E4-01` | ejemplos `/health/live` y `/health/ready` | `/api/health` compuesto | cero deriva OAS; health separado queda para change control |
| `DEV-E4-02` | topología fallback mostraba cinco packages | sólo `contracts`; datos dentro del adapter API | evita paquetes vacíos |
| `DEV-E4-03` | logs E0 14 d | logs E3/E4 7 d | IaC implementa requisito vigente |

Deuda no bloqueante local: contract suite compartida memoria/Dynamo, fijación razonada de flags CDK y runner cross-browser P1. Deuda/bloqueos externos: CI remota, branch protection, dominio/TLS, Budget/PITR y aprobaciones P0.

## 18. Evaluación GATE-E4-01

| Control | Resultado |
| --- | --- |
| workspace válido | `PASS` |
| versiones fijadas | `PASS` |
| lockfile único/frozen install | `PASS` |
| TypeScript strict | `PASS` |
| lint/formato | `PASS`, 0 errores |
| fronteras/ciclos | `PASS`, self-test + 0 violaciones |
| contratos incorporados | `PASS` |
| configuración validada | `PASS` |
| secretos | `PASS`, 0 hallazgos |

**Resultado: `GATE-E4-01 = PASS`.** Aprobado por `USER_DECISION_OWNER` el 2026-08-15.

## 19. Evaluación GATE-E4-02

| Control | Resultado |
| --- | --- |
| frontend inicia | `PASS` |
| backend inicia | `PASS` |
| health compuesto live/ready | `PASS` conforme OAS y `CHG-17` |
| semilla idempotente | `PASS` |
| endpoint producto conforme | `PASS` |
| UI usa API local real | `PASS` |
| `SMK-E4-01..06` | `PASS`, 6/6 |
| refresh | `PASS` |
| llamadas proveedor | `PASS`, 0 |
| logs/correlación | `PASS` |
| tests web/API/contrato | `PASS` |

**Resultado: `GATE-E4-02 = PASS`.** No existe falla del recorrido principal; aprobado por `USER_DECISION_OWNER` el 2026-08-15.

## 20. Evaluación GATE-E4-03

| Control | Umbral | Resultado |
| --- | ---: | --- |
| lint/typecheck | 0 | `PASS` |
| builds web/API | exitosos | `PASS` |
| cobertura web | ≥85×4 | `PASS` |
| cobertura API | ≥85×4 | `PASS` |
| OpenAPI/deriva | 0/0 | `PASS` |
| fronteras/ciclos | 0 | `PASS` |
| IaC tests/synth | 100 %/éxito | `PASS` |
| secretos | 0 | `PASS` |
| high/critical | 0/0 | `PASS` |
| smoke | 6/6 | `PASS` |
| artefactos físicos | 12/12 | `PASS`; aprobación/CI indicada por estado |
| evidencias documentadas | 17/17 | `PASS` |
| CI verde en commit/PR | requerida | `PASS`; `CI` y `Security` verdes sobre `a0f5e81` |
| decisiones P0 abiertas | 0 | `PASS`; aprobación recibida, `ADR-09` bloqueado sólo para integración real |

**Resultado: `GATE-E4-03 = BLOCKED`.** No se habilita formalmente la etapa 5. Los checks `CI / Summary` y `Security / Security` están verdes; sólo falta aplicar branch protection a `master`.

## 21. Handoff a etapa 5

Estado formal: `BLOCKED` por `GATE-E4-03`; no iniciar integración real ni sandbox. La foundation sí deja preparado el siguiente trabajo local una vez exista autorización:

1. producto/stock: ya vertical y reutilizable;
2. sesión de checkout y capability local;
3. cliente/entrega con campos confirmados;
4. cotización server-side;
5. transacción local `PENDING` y reserva atómica;
6. provider port mediante `FAKE-PAY-01..12`;
7. polling/reconciliación fake;
8. efectos APPROVED/DECLINED/ERROR/VOIDED;
9. recuperación tras refresh;
10. sólo después de `SPK-02` y autorizaciones: adapter sandbox.

Interfaces disponibles:

- `CatalogRepository` con memoria y Dynamo local;
- `PaymentProvider` sin red;
- `Result<T,E>` y errores RFC 9457;
- `baseApi` RTK Query;
- tipos `components`, `paths`, `operations`, `webhooks`;
- CDK fake-only y CI bloqueante sin cloud authority.

Comandos de handoff: `pnpm bootstrap`, `pnpm dev`, `pnpm seed`, `pnpm verify`, `pnpm test:smoke`, `pnpm infra:synth`. No ejecutar `cdk deploy/bootstrap/destroy`, comandos AWS, dashboard del proveedor ni requests sandbox.

Acciones del owner antes de E5:

1. revisar y firmar `CHG-17`, `DEC-E4-*`, gates y campos P0;
2. crear remoto neutral autorizado, ejecutar CI y proteger `main`;
3. conservar el adapter real bloqueado hasta `AUTH-01/AUTH-02` y `SPK-02`;
4. resolver dominio/TLS, presupuesto, PITR y región antes de cualquier release.

El repositorio remoto público conserva el historial temático y el merge del PR #1; no hubo llamada de proveedor ni mutación AWS asociada a esta entrega.
